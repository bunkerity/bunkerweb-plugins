package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

// errReader fails on the first Read, to exercise the body-read error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, fmt.Errorf("forced read error") }

// newTestWAF builds a self-contained WAF from inline directives so tests never
// depend on the vendored coreruleset/ (gitignored, only present after a Docker
// build).
func newTestWAF(t *testing.T, directives string) coraza.WAF {
	t.Helper()
	w, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("failed to build test WAF: %v", err)
	}
	return w
}

func corazaHeaders(req *http.Request, id, method, uri string) {
	req.Header.Set("X-Coraza-Version", "HTTP/1.1")
	req.Header.Set("X-Coraza-Method", method)
	req.Header.Set("X-Coraza-Ip", "127.0.0.1")
	req.Header.Set("X-Coraza-Id", id)
	req.Header.Set("X-Coraza-Uri", uri)
}

func decodeResp(t *testing.T, rec *httptest.ResponseRecorder) Resp {
	t.Helper()
	var resp Resp
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid JSON response %q: %v", rec.Body.String(), err)
	}
	return resp
}

const argsRule = `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS "@contains attackpattern" "id:1,phase:2,deny,status:403,msg:'args rule'"
`

const headerRule = `
SecRuleEngine On
SecRule REQUEST_HEADERS:X-Test "@streq bad" "id:2,phase:1,deny,status:403,msg:'header rule'"
`

const bodyRule = `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS_POST:payload "@contains attackpattern" "id:3,phase:2,deny,status:403,msg:'body rule'"
`

func TestHandlePing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	handlePing(rec, req)

	var pong Pong
	if err := json.NewDecoder(rec.Body).Decode(&pong); err != nil {
		t.Fatalf("invalid JSON response %q: %v", rec.Body.String(), err)
	}
	if pong.Pong != "ok" {
		t.Fatalf("expected pong=ok, got %q", pong.Pong)
	}
}

func TestHandleRequest_Benign(t *testing.T) {
	waf = newTestWAF(t, argsRule)
	req := httptest.NewRequest(http.MethodGet, "/request", nil)
	corazaHeaders(req, "benign", "GET", "/?q=hello")
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	resp := decodeResp(t, rec)
	if resp.Deny {
		t.Fatalf("expected deny=false for benign request, got %+v", resp)
	}
}

func TestHandleRequest_ArgsDeny(t *testing.T) {
	waf = newTestWAF(t, argsRule)
	req := httptest.NewRequest(http.MethodGet, "/request", nil)
	corazaHeaders(req, "args-deny", "GET", "/?q=attackpattern")
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	resp := decodeResp(t, rec)
	if !resp.Deny {
		t.Fatalf("expected deny=true for malicious args, got %+v", resp)
	}
	if !strings.Contains(resp.Msg, "rule ID 1") {
		t.Fatalf("expected msg to mention rule ID 1, got %q", resp.Msg)
	}
}

func TestHandleRequest_HeaderDeny(t *testing.T) {
	waf = newTestWAF(t, headerRule)
	req := httptest.NewRequest(http.MethodGet, "/request", nil)
	corazaHeaders(req, "header-deny", "GET", "/")
	// X-Coraza-Header-* are stripped of the prefix and added as request headers.
	req.Header.Set("X-Coraza-Header-X-Test", "bad")
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	resp := decodeResp(t, rec)
	if !resp.Deny {
		t.Fatalf("expected deny=true for phase-1 header match, got %+v", resp)
	}
}

func TestHandleRequest_BodyDeny(t *testing.T) {
	waf = newTestWAF(t, bodyRule)
	req := httptest.NewRequest(http.MethodPost, "/request", strings.NewReader("payload=attackpattern"))
	corazaHeaders(req, "body-deny", "POST", "/")
	// BunkerWeb forwards the real request headers prefixed with X-Coraza-Header-;
	// coraza needs the Content-Type to pick the urlencoded body processor.
	req.Header.Set("X-Coraza-Header-Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	resp := decodeResp(t, rec)
	if !resp.Deny {
		t.Fatalf("expected deny=true for malicious body, got %+v", resp)
	}
}

func TestHandleRequest_RuleEngineOff(t *testing.T) {
	waf = newTestWAF(t, "SecRuleEngine Off")
	req := httptest.NewRequest(http.MethodGet, "/request", nil)
	corazaHeaders(req, "engine-off", "GET", "/?q=attackpattern")
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	resp := decodeResp(t, rec)
	if resp.Deny {
		t.Fatalf("expected deny=false when rule engine off, got %+v", resp)
	}
	if resp.Msg != "rule engine is set to off" {
		t.Fatalf("expected rule-engine-off message, got %q", resp.Msg)
	}
}

func TestHandleRequest_BodyReadError(t *testing.T) {
	waf = newTestWAF(t, "SecRuleEngine On\nSecRequestBodyAccess On")
	req := httptest.NewRequest(http.MethodPost, "/request", errReader{})
	corazaHeaders(req, "body-error", "POST", "/")
	req.Header.Set("X-Coraza-Header-Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on body read error, got %d (%q)", rec.Code, rec.Body.String())
	}
}

const limitRule = `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 128
SecRequestBodyLimitAction Reject
`

func TestHandleRequest_OversizedBody(t *testing.T) {
	waf = newTestWAF(t, limitRule)
	big := strings.Repeat("A", 4096)
	req := httptest.NewRequest(http.MethodPost, "/request", strings.NewReader("payload="+big))
	corazaHeaders(req, "oversized", "POST", "/")
	req.Header.Set("X-Coraza-Header-Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	// Must not panic and must return a well-formed result (deny or 500), never a
	// silent pass of an over-limit body.
	if rec.Code == http.StatusOK {
		resp := decodeResp(t, rec)
		if !resp.Deny {
			t.Fatalf("expected an over-limit body to be denied, got %+v", resp)
		}
	} else if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 200(deny) or 500 for oversized body, got %d", rec.Code)
	}
}
