package main

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"regexp"
)

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "templates/adminLogin.html")
		return
	} else if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		err = db.QueryRow("SELECT 1 FROM admins WHERE username=? AND PASSWORD=?", username, hashPassword(password)).Scan(new(int))
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "admin_session",
			Value:    base64.StdEncoding.EncodeToString([]byte(username + ":" + hashPassword(password))),
			Path:     "/admin/",
			HttpOnly: true,
			MaxAge:   3600})
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}
}

func adminLogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: "", Path: "/admin/", HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func isAdmin(r *http.Request) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return false
	}
	var username, passwordHash string
	regexp := regexp.MustCompile(`^([^:]+):([a-f0-9]+)$`)
	matches := regexp.FindStringSubmatch(string(decoded))
	if len(matches) != 3 {
		return false
	}
	username = matches[1]
	passwordHash = matches[2]
	err = db.QueryRow("SELECT 1 FROM admins WHERE username=? AND PASSWORD=?", username, passwordHash).Scan(new(int))
	return err != sql.ErrNoRows && err == nil
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	w.Write([]byte("Welcome to the admin panel!"))
}
