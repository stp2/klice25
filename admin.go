package main

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"regexp"
)

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		http.ServeFile(w, r, "templates/adminLogin.html")
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		err := db.QueryRow(
			"SELECT 1 FROM admins WHERE username=? AND PASSWORD=?",
			username, hashPassword(password),
		).Scan(new(int))
		switch {
		case err == sql.ErrNoRows:
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		case err != nil:
			http.Error(w, "Database error", http.StatusInternalServerError)
		default:
			http.SetCookie(w, &http.Cookie{
				Name:     "admin_session",
				Value:    base64.StdEncoding.EncodeToString([]byte(username + ":" + hashPassword(password))),
				Path:     "/admin/",
				HttpOnly: true,
				MaxAge:   3600,
			})
			http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminLogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: "", Path: "/admin/", HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func isAdmin(w http.ResponseWriter, r *http.Request) bool {
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
	if err != sql.ErrNoRows && err == nil {
		return true
	}
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
	return false
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(w, r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	http.ServeFile(w, r, "templates/adminPanel.html")
}

func adminTeamsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(w, r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	rows, err := db.Query("SELECT name, difficulty_levels.level_name, last_cipher, penalty FROM teams JOIN difficulty_levels ON teams.difficulty_level = difficulty_levels.id ORDER BY name")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var teams []TeamTemplateS
	for rows.Next() {
		var team TeamTemplateS
		if err := rows.Scan(&team.TeamName, &team.Difficulty, &team.LastCipher, &team.Penalties); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		teams = append(teams, team)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if err := AdminTeamsTemplate.Execute(w, teams); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func AdminStartHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(w, r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	_, err := db.Exec("UPDATE teams SET last_cipher = 1, penalty = 0")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("DELETE FROM penalties")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}
