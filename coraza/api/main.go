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

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
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

	var triggeredRules []string
	for _, rule := range rules {
		if rule.Message() != "" {
			triggeredRules = append(triggeredRules, rule.AuditLog())
		}
	}

	if len(triggeredRules) > 0 {
		InfoLogger.Printf("Règles déclenchées: %s\n", strings.Join(triggeredRules, ", "))
	}

	switch action {
	case "block", "deny", "drop", "redirect", "reject":
		data := Resp{
			Deny: true,
			Msg:  fmt.Sprintf("%s action from rule ID %d", action, ruleid),
		}
		json.NewEncoder(w).Encode(data)
		return
	case "allow":
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
	InfoLogger.Printf("GET /ping")
	data := Pong{
		Pong: "ok",
	}
	json.NewEncoder(w).Encode(data)
}

func handleRequest(w http.ResponseWriter, req *http.Request) {
	InfoLogger.Printf("POST /request")
	uri := req.RequestURI

	version := "HTTP/1.1"

	txid := req.Header.Get("X_CORAZA_ID")

	InfoLogger.Printf("[%s] Processing request with ip=%s, uri=%s, method=%s and version=%s", txid, req.Header.Get("X_CORAZA_IP"), uri, req.Header.Get("X_CORAZA_METHOD"), version)
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

	tx.ProcessConnection(req.Header.Get("X_CORAZA_IP"), 42000, "", 0)
	tx.ProcessURI(uri, req.Header.Get("X_CORAZA_METHOD"), version)
	for name, values := range req.Header {
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}
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
			InfoLogger.Printf("ici le body [%s]", "erreur")

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
	data := Resp{
		Deny: false,
		Msg:  "pass",
	}

	json.NewEncoder(w).Encode(data)
	InfoLogger.Printf("[%s] Request processed", txid)
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
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRequest)
	InfoLogger.Printf("Coraza API is ready to handle requests")
	http.ListenAndServe(":8080", mux)
}
