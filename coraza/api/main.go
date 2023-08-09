package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"golang.org/x/exp/slices"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
)

var (
	InfoLogger    *log.Logger
	WarningLogger *log.Logger
	ErrorLogger   *log.Logger
)

type Pong struct {
	Pong string `json:"pong"`
}

type Resp struct {
	Deny bool   `json:"deny"`
	Msg  string `json:"msg"`
}

var waf coraza.WAF

func processInterruption(w http.ResponseWriter, tx types.Transaction, it *types.Interruption) {
	action := it.Action
	ruleid := it.RuleID
	rules := tx.MatchedRules()
	txid := tx.ID()

	for _, rule := range rules {
		if rule.Message() != "" {
			WarningLogger.Printf(rule.AuditLog())
		}
	}

	switch action {
		case "block", "deny", "drop", "redirect", "reject":
			WarningLogger.Printf("[%s] %s action from rule ID %d", txid, action, ruleid)
			data := Resp{
				Deny: true,
				Msg:  fmt.Sprintf("%s action from rule ID %d", action, ruleid),
			}
			json.NewEncoder(w).Encode(data)
			return
		case "allow":
			InfoLogger.Printf("[%s] %s action from rule ID %d", txid, action, ruleid)
			data := Resp{
				Deny: false,
				Msg:  fmt.Sprintf("allow action from rule ID %d", ruleid),
			}
			json.NewEncoder(w).Encode(data)
			return
	}
	ErrorLogger.Printf("[%s] Unknown %s action from rule ID %d", txid, action, ruleid)
}

func handlePing(w http.ResponseWriter, req *http.Request) {
	InfoLogger.Printf("Ping received")
	data := Pong{
		Pong: "ok",
	}
	json.NewEncoder(w).Encode(data)
}

func handleRequest(w http.ResponseWriter, req *http.Request) {
	InfoLogger.Printf("Request received")
	uri := strings.Replace(req.RequestURI, "/request", "", 1)
	version := req.Header.Get("X_CORAZA_VERSION")
	method := req.Header.Get("X_CORAZA_METHOD")
	ip := req.Header.Get("X_CORAZA_IP")
	txid := req.Header.Get("X_CORAZA_ID")

	InfoLogger.Printf("Host = %s", req.Host)
	InfoLogger.Printf("[%s] Processing request with ip=%s, uri=%s, method=%s and version=%s", txid, ip, uri, method, version)
	tx := waf.NewTransactionWithID(txid)
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			ErrorLogger.Printf("[%s] Failed to close transaction : %s", txid, err.Error())
		}
	}()
	if tx.IsRuleEngineOff() {
		InfoLogger.Printf("[%s] Rule engine is set to off", txid)
		data := Resp{
			Deny: false,
			Msg:  "rule engine is set to off",
		}
		json.NewEncoder(w).Encode(data)
		return
	}

	InfoLogger.Printf("[%s] Processing phase 1", txid)

	tx.ProcessConnection(ip, 42000, "", 0)
	tx.ProcessURI(uri, method, version)
	coraza_headers := []string{"X_CORAZA_VERSION", "X_CORAZA_METHOD", "X_CORAZA_IP", "X_CORAZA_ID"}
	for name, values := range req.Header {
		if !slices.Contains(coraza_headers, strings.ToUpper(name)) {
			for _, value := range values {
				tx.AddRequestHeader(name, value)
			}
		}
	}
	tx.AddRequestHeader("Host", req.Host)
	if it := tx.ProcessRequestHeaders(); it != nil {
		processInterruption(w, tx, it)
		return
	}
	InfoLogger.Printf("[%s] Processing phase 2", txid)
	var bodyreason = ""
	if !tx.IsRequestBodyAccessible() {
		bodyreason = "RequestBodyAccess disabled"
	}

	if req.Body == nil || req.Body == http.NoBody {
		bodyreason = "no body"
	}
	if bodyreason == "" {
		InfoLogger.Printf("[%s] Reading body", txid)

		bodyBytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			ErrorLogger.Printf("[%s] Error while reading body : %s", txid, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		bodyString := string(bodyBytes)

		it, _, err := tx.ReadRequestBodyFrom(strings.NewReader(bodyString))
		if it != nil {
			processInterruption(w, tx, it)
			return
		}

		if it != nil {
			processInterruption(w, tx, it)
			return
		}

		if err != nil {
			ErrorLogger.Printf("[%s] Failed to append request body : %s", txid, err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		rbr, err := tx.RequestBodyReader()
		if err != nil {
			ErrorLogger.Printf("Failed to get the request body: %s", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body := io.MultiReader(rbr, req.Body)
		if rwt, ok := body.(io.WriterTo); ok {
			req.Body = struct {
				io.Reader
				io.WriterTo
				io.Closer
			}{body, rwt, req.Body}
		}
	} else {
		InfoLogger.Printf("[%s] Not reading body (%s)", txid, bodyreason)
	}
	it, err := tx.ProcessRequestBody()
	if it != nil {
		processInterruption(w, tx, it)
		return
	}
	if err != nil {
		ErrorLogger.Printf("[%s] Failed to process request body : %s", txid, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	InfoLogger.Printf("[%s] Request processed without action", txid)
	data := Resp{
		Deny: false,
		Msg:  "pass",
	}
	json.NewEncoder(w).Encode(data)
}

func loggingMiddleware(next http.Handler) http.Handler {
    return handlers.LoggingHandler(os.Stdout, next)
}

func main() {
	InfoLogger = log.New(os.Stdout, "INFO: ", log.LstdFlags)
	WarningLogger = log.New(os.Stdout, "WARNING: ", log.LstdFlags)
	ErrorLogger = log.New(os.Stdout, "ERROR: ", log.LstdFlags)
	var err error
	waf, err = coraza.NewWAF(
		coraza.NewWAFConfig().
			WithDirectivesFromFile("coraza.conf").
			WithDirectivesFromFile("bunkerweb.conf").
			WithDirectivesFromFile("/rules-before/*.conf").
			WithDirectivesFromFile("coreruleset/crs-setup.conf.example").
			WithDirectivesFromFile("coreruleset/rules/*.conf").
			WithDirectivesFromFile("/rules-after/*.conf"))
	if err != nil {
		ErrorLogger.Printf("Error while initalizing Coraza : %s", err.Error())
		os.Exit(1)
	}
	r := mux.NewRouter()
	// request := r.PathPrefix("/request").Subrouter()
	// request.Path("/{uri}").HandlerFunc(handleRequest)
	r.PathPrefix("/request").HandlerFunc(handleRequest)
	r.HandleFunc("/ping", handlePing)
	r.Use(loggingMiddleware)
	r.NotFoundHandler = r.NewRoute().HandlerFunc(http.NotFound).GetHandler()
	InfoLogger.Printf("Coraza API is ready to handle requests")
	srv := &http.Server{
        Handler:      r,
        Addr:         "0.0.0.0:8080",
        WriteTimeout: 15 * time.Second,
        ReadTimeout:  15 * time.Second,
    }
	srv.ListenAndServe()
}
