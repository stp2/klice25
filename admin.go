package main

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"regexp"
)

type difficultyLevel struct {
	ID        int
	LevelName string
}

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
	if err != sql.ErrNoRows && err == nil {
		return true
	}
	return false
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	http.ServeFile(w, r, "templates/adminPanel.html")
}

func adminTeamsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		// Deleting an existing team
		if r.PostForm.Has("delete") {
			teamName := r.FormValue("delete")
			_, err := db.Exec("DELETE FROM teams WHERE name = ?", teamName)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/teams", http.StatusSeeOther)
			return
		}
		// Adding a new team
		teamName := r.FormValue("name")
		difficulty := r.FormValue("difficulty")
		password := r.FormValue("password")
		if teamName == "" || difficulty == "" || password == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}
		_, err := db.Exec("INSERT INTO teams (name, difficulty_level, password, last_cipher, penalty) VALUES (?, ?, ?, 1, 0)", teamName, difficulty, hashPassword(password))
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/teams", http.StatusSeeOther)
		return
	}
	// Fetch all teams with their difficulty levels
	// Teams
	rows, err := db.Query("SELECT name, difficulty_levels.level_name, last_cipher, penalty FROM teams JOIN difficulty_levels ON teams.difficulty_level = difficulty_levels.id ORDER BY teams.difficulty_level, teams.name")
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
	// Difficulty levels for the dropdown
	rows, err = db.Query("SELECT id, level_name FROM difficulty_levels ORDER BY id")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var difficultyLevels []DifficultyLevelS
	for rows.Next() {
		var level DifficultyLevelS
		if err := rows.Scan(&level.ID, &level.Name); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		difficultyLevels = append(difficultyLevels, level)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	teamsData := TeamsTemplateS{
		Teams:        teams,
		Difficulties: difficultyLevels,
	}
	if err := AdminTeamsTemplate.Execute(w, teamsData); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func AdminStartHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
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

func AdminRouteHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	// Fetch all difficulty levels
	rows, err := db.Query("SELECT id, level_name FROM difficulty_levels ORDER BY id")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var difficultyLevels []difficultyLevel
	for rows.Next() {
		var level difficultyLevel
		if err := rows.Scan(&level.ID, &level.LevelName); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		difficultyLevels = append(difficultyLevels, level)
	}
	// For each difficulty level, fetch the corresponding tasks and their details
	var routes []AdminRoutesTemplateS
	for _, level := range difficultyLevels {
		var route AdminRoutesTemplateS
		rows, err := db.Query("SELECT tasks.order_num, CIPHERS.assignment, CIPHERS.clue, tasks.end_clue, POSITIONS.gps, POSITIONS.clue, CIPHERS.solution FROM TASKS JOIN CIPHERS ON TASKS.cipher_id = ciphers.id JOIN POSITIONS on TASKS.position_id = POSITIONS.id WHERE TASKS.difficulty_level=? ORDER BY TASKS.order_num;", level.ID)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		route.Name = level.LevelName
		for rows.Next() {
			var cipher CipherTemplateS
			if err := rows.Scan(&cipher.Order, &cipher.Assignment, &cipher.HelpText, &cipher.FinalClue, &cipher.Coordinates, &cipher.PositionHint, &cipher.Solution); err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			route.Ciphers = append(route.Ciphers, cipher)
		}
		if err := rows.Err(); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		routes = append(routes, route)
	}
	if err := AdminRoutesTemplate.Execute(w, routes); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func AdminLevelHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		// Deleting an existing difficulty level
		if r.PostForm.Has("delete") {
			levelName := r.FormValue("delete")
			_, err := db.Exec("DELETE FROM difficulty_levels WHERE level_name = ?", levelName)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/levels", http.StatusSeeOther)
			return
		}
		// Adding a new difficulty level
		levelName := r.FormValue("name")
		if levelName == "" {
			http.Error(w, "Level name cannot be empty", http.StatusBadRequest)
			return
		}
		_, err := db.Exec("INSERT INTO difficulty_levels (level_name) VALUES (?)", levelName)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/levels", http.StatusSeeOther)
		return
	}
	rows, err := db.Query("SELECT level_name FROM difficulty_levels ORDER BY id")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var difficultyLevels []string
	for rows.Next() {
		var level string
		if err := rows.Scan(&level); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		difficultyLevels = append(difficultyLevels, level)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if err := AdminLevelTemplate.Execute(w, difficultyLevels); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func AdminCipherHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		// Deleting an existing cipher
		if r.PostForm.Has("delete") {
			cipherID := r.FormValue("delete")
			_, err := db.Exec("DELETE FROM ciphers WHERE id = ?", cipherID)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/cipher", http.StatusSeeOther)
			return
		}
		// Adding a new cipher
		assignment := r.FormValue("assignment")
		solution := r.FormValue("solution")
		clue := r.FormValue("clue")
		if assignment == "" || solution == "" || clue == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}
		_, err := db.Exec("INSERT INTO ciphers (assignment, solution, clue) VALUES (?, ?, ?)", assignment, solution, clue)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/cipher", http.StatusSeeOther)
		return
	}
	rows, err := db.Query("SELECT id, assignment, solution, clue FROM ciphers ORDER BY id")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var ciphers []AdminCipherTemplateS
	for rows.Next() {
		var cipher AdminCipherTemplateS
		if err := rows.Scan(&cipher.ID, &cipher.Assignment, &cipher.Solution, &cipher.Clue); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		ciphers = append(ciphers, cipher)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if err := AdminCipherTemplate.Execute(w, ciphers); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func AdminPositionsHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		// Deleting an existing position
		if r.PostForm.Has("delete") {
			positionID := r.FormValue("delete")
			_, err := db.Exec("DELETE FROM positions WHERE id = ?", positionID)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/positions", http.StatusSeeOther)
			return
		}
		// Adding a new position
		gps := r.FormValue("gps")
		clue := r.FormValue("clue")
		if gps == "" || clue == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}
		_, err := db.Exec("INSERT INTO positions (gps, clue) VALUES (?, ?)", gps, clue)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/positions", http.StatusSeeOther)
		return
	}
	rows, err := db.Query("SELECT positions.id, gps, clue, COALESCE(uid, '') FROM positions LEFT JOIN QR_CODES ON positions.id = QR_CODES.position_id ORDER BY positions.id")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var positions []AdminPositionsTemplateS
	for rows.Next() {
		var position AdminPositionsTemplateS
		if err := rows.Scan(&position.ID, &position.GPS, &position.Clue, &position.URL); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		position.URL = domain + "/qr/" + position.URL
		positions = append(positions, position)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if err := AdminPositionsTemplate.Execute(w, positions); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}

func AdminQRHandler(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		// Deleting an existing QR code
		if r.PostForm.Has("delete") {
			qrID := r.FormValue("delete")
			_, err := db.Exec("DELETE FROM qr_codes WHERE id = ?", qrID)
			if err != nil {
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/admin/qr", http.StatusSeeOther)
			return
		}
		// Adding a new QR code
		positionID := r.FormValue("position")
		uid := r.FormValue("uid")
		if positionID == "" || uid == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}
		_, err := db.Exec("INSERT INTO qr_codes (position_id, uid) VALUES (?, ?)", positionID, uid)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/admin/qr", http.StatusSeeOther)
		return
	}
	// Fetch all QR codes with their associated positions
	rows, err := db.Query("SELECT qr_codes.id, qr_codes.uid, COALESCE(position_id, ''), COALESCE(gps, '') FROM qr_codes LEFT JOIN positions ON qr_codes.position_id = positions.id ORDER BY qr_codes.id")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var qrs []AdminQRsTemplateS
	for rows.Next() {
		var qr AdminQRsTemplateS
		if err := rows.Scan(&qr.ID, &qr.URL, &qr.Position, &qr.GPS); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		qr.URL = domain + "/qr/" + qr.URL
		qrs = append(qrs, qr)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	// Fetch all positions for the dropdown
	rows, err = db.Query("SELECT id FROM positions ORDER BY id")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var positions []int
	for rows.Next() {
		var position int
		if err := rows.Scan(&position); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		positions = append(positions, position)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if err := AdminQRsTemplate.Execute(w, AdminQRTemplateS{QRs: qrs, Positions: positions}); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
}
