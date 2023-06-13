package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"fmt"
	"os"
	//"github.com/gorilla/mux"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	//"github.com/julienschmidt/httprouter"
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
	Deny bool `json:"deny"`
	Msg string `json:"msg"`
}

var waf coraza.WAF

func processInterruption(w http.ResponseWriter, tx types.Transaction, it *types.Interruption) {
	action := it.Action
	ruleid := it.RuleID
	rules := tx.MatchedRules()
	txid := tx.ID()
	for _, rule := range rules {
		if rule.AuditLog() != "" {
			WarningLogger.Printf(rule.AuditLog())
		}
	}
	switch action {
		case "block", "deny", "drop", "redirect", "reject":
			data := Resp{
				Deny: true,
				Msg: fmt.Sprintf("%s action from rule ID %d", action, ruleid),
			}
			json.NewEncoder(w).Encode(data)
			return
		case "allow":
			data := Resp{
				Deny: false,
				Msg: fmt.Sprintf("allow action from rule ID %d", ruleid),
			}
			json.NewEncoder(w).Encode(data)
			return
  	}
	ErrorLogger.Printf("[%s] Unknown %s action from rule ID %d", txid, action, ruleid)
}

func handlePing(w http.ResponseWriter, req *http.Request/*, _ httprouter.Params*/) {
	// Send pong response
	InfoLogger.Printf("GET /ping")
	data := Pong{
		Pong: "ok",
	}
	json.NewEncoder(w).Encode(data)
}

func handleRequest(w http.ResponseWriter, req *http.Request/*, _ httprouter.Params*/) {
	// Get headers
	//vars := mux.Vars(req)
	InfoLogger.Printf("POST /request")
	txid := "toto" // req.Header.Get("X-Coraza-ID")
	ip := "127.0.0.1" // req.Header.Get("X-Coraza-IP")
	uri := req.RequestURI // req.Header.Get("X-Coraza-URI")
	// if uri == "" {
	// 	uri = "/"
	// }
 	method := req.Method // req.Header.Get("X-Coraza-METHOD")
	version := "HTTP/1.1" // req.Header.Get("X-Coraza-VERSION")
	// Loop over header names

	// headers_str := req.Header.Get("X-Coraza-HEADERS")
	// var headers map[string]interface{}
	// err := json.Unmarshal([]byte(headers_str), &headers)
	// if err != nil {
	// 	ErrorLogger.Printf(err.Error())
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return
	// }
	// Create transaction
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
			Msg: "rule engine is set to off",
		}
		json.NewEncoder(w).Encode(data)
		return
	}
	// Phase 1
	InfoLogger.Printf("[%s] Processing phase 1", txid)
	tx.ProcessConnection(ip, 42000, "", 0)
	tx.ProcessURI(uri, method, version)
	for name, values := range req.Header {
		// Loop over all values for the name.
		for _, value := range values {
			tx.AddRequestHeader(name, value)
		}
	}
	// for key, value := range headers {
	// 	tx.AddRequestHeader(key, value.(string))
	// }
	if it := tx.ProcessRequestHeaders();it != nil {
		processInterruption(w, tx, it)
		return
	}
	// Phase 2
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
		it, _, err := tx.ReadRequestBodyFrom(req.Body)
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
			ErrorLogger.Printf("[%s] Failed to get the request body: %s", err.Error())
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
		} else {
			req.Body = struct {
				io.Reader
				io.Closer
			}{body, req.Body}
		}
	} else {
		InfoLogger.Printf("[%s] Not reading body (%s)", txid, bodyreason)
	}
	it, err := tx.ProcessRequestBody();
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
		Msg: "pass",
	}
	json.NewEncoder(w).Encode(data)
	InfoLogger.Printf("[%s] Request processed", txid)
}

func main() {

	// Setup loggers
	InfoLogger = log.New(os.Stdout, "INFO: ", log.LstdFlags)
	WarningLogger = log.New(os.Stdout, "WARNING: ", log.LstdFlags)
	ErrorLogger = log.New(os.Stdout, "ERROR: ", log.LstdFlags)

	// Setup Coraza
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

	// Setup HTTP server
    mux := http.NewServeMux()
    mux.HandleFunc("/", handleRequest)
    mux.HandleFunc("/ping", handlePing)
    // router.GET("/ping", handlePing)
    // router.POST("/request", handleRequest)
	// TODO : handle response too
	// srv := &http.Server{
	// 	Addr: ":8080",
	// 	Handler: router,
	// }
	// http.Handle("/", router)
	InfoLogger.Printf("Coraza API is ready to handle requests")
	http.ListenAndServe(":8080", mux)
}