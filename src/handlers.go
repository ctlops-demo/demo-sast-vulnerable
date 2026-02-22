// INTENTIONALLY VULNERABLE — Go HTTP handlers for SAST scanner demo.
//
// Every function contains security vulnerabilities that Opengrep/CodeQL should flag.
// DO NOT use this code in production.

package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os/exec"
)

var db *sql.DB

// ─── SQL Injection (Go) ──────────────────────────────────────
// VULN: String concatenation in SQL query
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	query := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "OK")
}

// ─── Command Injection (Go) ──────────────────────────────────
// VULN: User input passed to exec.Command with shell
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c 3 "+host).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

// ─── Path Traversal (Go) ─────────────────────────────────────
// VULN: User-controlled file path
func readFileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(data)
}

// ─── Cross-Site Scripting (Go) ───────────────────────────────
// VULN: User input rendered as HTML without escaping
func searchHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	// Using text/template instead of html/template — no auto-escaping
	tmpl := template.Must(template.New("search").Parse(
		`<html><body><h1>Results for: {{.}}</h1></body></html>`,
	))
	tmpl.Execute(w, template.HTML(query)) // VULN: template.HTML bypasses escaping
}

// ─── SSRF (Go) ───────────────────────────────────────────────
// VULN: User-controlled URL fetched without validation
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

// ─── Open Redirect (Go) ─────────────────────────────────────
// VULN: Unvalidated redirect target
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	http.Redirect(w, r, target, http.StatusFound)
}

// ─── Information Disclosure ──────────────────────────────────
// VULN: Detailed error messages with internal paths
func debugHandler(w http.ResponseWriter, r *http.Request) {
	_, err := db.Query("SELECT 1")
	if err != nil {
		// Exposes internal database error to client
		fmt.Fprintf(w, "Database error: %v\nConnection: %s", err, db.Stats())
	}
}
