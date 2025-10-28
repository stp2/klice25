package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const domain = "https://klice.h21.cz"
const dbFile = "./klice.db"

const (
	smallHelpPenalty = 5
	giveUpPenalty    = 30
)

var db *sql.DB

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Could not parse form", http.StatusBadRequest)
			return
		}
		password := r.FormValue("password")
		hashedPassword := hashPassword(password)

		err := db.QueryRow("SELECT 1 FROM teams WHERE password = ?", hashedPassword).Scan(new(int))
		switch {
		case err == sql.ErrNoRows:
			http.Error(w, "No team found", http.StatusUnauthorized)
			return
		case err != nil:
			http.Error(w, "Could not retrieve team", http.StatusInternalServerError)
			return
		default:
			sessionID := hashedPassword
			cookie := &http.Cookie{
				Name:     "session_id",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			}
			http.SetCookie(w, cookie)

			redir, err := r.Cookie("url")
			if err == nil {
				redir.MaxAge = -1
				http.SetCookie(w, redir)
				http.Redirect(w, r, redir.Value, http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/team", http.StatusSeeOther)
			}
		}
	case http.MethodGet:
		http.ServeFileFS(w, r, templatesFS, "templates/login.html")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func isLoggedIn(w http.ResponseWriter, r *http.Request) (bool, int) {
	var exist bool = true
	var teamID int
	cookie, err := r.Cookie("session_id")
	if err != nil {
		exist = false
	} else {
		err = db.QueryRow("SELECT id FROM teams WHERE password = ?", cookie.Value).Scan(&teamID)
		if err == sql.ErrNoRows {
			exist = false
		} else if err != nil {
			exist = false
		}
	}

	if !exist {
		redir := &http.Cookie{
			Name:     "url",
			Value:    r.URL.String(),
			MaxAge:   300,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, redir)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false, 0
	}
	return true, teamID
}

func teamInfoHandler(w http.ResponseWriter, r *http.Request) {
	if loggedIn, teamID := isLoggedIn(w, r); loggedIn {
		var teamName string
		var difficultyLevel string
		var lastCipher int
		var penalty int

		err := db.QueryRow("SELECT name, level_name, last_cipher, penalty FROM teams JOIN difficulty_levels ON teams.difficulty_level = difficulty_levels.id WHERE teams.id = ?", teamID).Scan(&teamName, &difficultyLevel, &lastCipher, &penalty)
		if err != nil {
			http.Error(w, "Could not retrieve team info", http.StatusInternalServerError)
			return
		}

		TeamTemplateData := TeamTemplateS{
			TeamName:   teamName,
			Difficulty: difficultyLevel,
			LastCipher: lastCipher,
			Penalties:  penalty,
		}

		err = TeamTemplate.Execute(w, TeamTemplateData)
		if err != nil {
			http.Error(w, "Could not render template", http.StatusInternalServerError)
			return
		}
	}
}

func qrHandler(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("qr")
	if uid == "" {
		http.Error(w, "Invalid QR code", http.StatusBadRequest)
		return
	}
	var positionID int
	err := db.QueryRow("SELECT position_id FROM qr_codes WHERE uid = ?", uid).Scan(&positionID)
	if err == sql.ErrNoRows {
		http.Error(w, "QR code not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Could not retrieve position", http.StatusInternalServerError)
		return
	}
	if loggedIn, teamID := isLoggedIn(w, r); loggedIn {
		var assignment string
		var cipherID int
		var taskID int
		var order int
		var last_cipher int
		var help int = 0
		var penalty int = 0

		// Find task for this position and team's difficulty level
		err = db.QueryRow("SELECT id FROM TASKS WHERE position_id = ? AND difficulty_level = (SELECT difficulty_level FROM teams WHERE id = ?)", positionID, teamID).Scan(&taskID)
		if err == sql.ErrNoRows {
			http.Error(w, "No task found for this position and team", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "Could not retrieve task", http.StatusInternalServerError)
			return
		}
		// get task order
		err = db.QueryRow("SELECT order_num FROM TASKS WHERE id = ?", taskID).Scan(&order)
		if err != nil {
			http.Error(w, "Could not retrieve task order", http.StatusInternalServerError)
			return
		}
		// get last cipher visited by team
		err = db.QueryRow("SELECT last_cipher FROM teams WHERE id = ?", teamID).Scan(&last_cipher)
		if err != nil {
			http.Error(w, "Could not retrieve last cipher", http.StatusInternalServerError)
			return
		}
		// check if the task is available for the team
		// if order > last_cipher, task is not yet available
		// if order == last_cipher, task is now available
		// if order <= last_cipher, task has been already visited, allow viewing
		if order > last_cipher {
			http.Error(w, "This task is not yet available", http.StatusForbidden)
			return
		} else if order == last_cipher {
			_, err := db.Exec("UPDATE teams SET last_loaded_cipher = ? WHERE id = ?", order, teamID)
			if err != nil {
				http.Error(w, "Could not update last loaded cipher", http.StatusInternalServerError)
				return
			}

		} else if order < last_cipher {
			help = 2
		}
		// get cipher assignment
		err = db.QueryRow("SELECT id, assignment FROM CIPHERS WHERE id = (SELECT cipher_id FROM TASKS WHERE id = ?)", taskID).Scan(&cipherID, &assignment)
		if err == sql.ErrNoRows {
			http.Error(w, "No cipher found", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "Could not retrieve cipher", http.StatusInternalServerError)
			return
		}

		CipherTemplateData := CipherTemplateS{
			Order:       uint(order),
			Assignment:  template.HTML(assignment),
			HelpText:    "",
			FinalClue:   "",
			Coordinates: "",
			Solution:    "",
			Wrong:       false,
		}

		// get penalties for this task and team
		err = db.QueryRow("SELECT minutes FROM penalties WHERE team_id = ? AND task_id = ?", teamID, taskID).Scan(&penalty)
		if err == sql.ErrNoRows {
			penalty = 0
		} else if err != nil {
			http.Error(w, "Could not retrieve penalties", http.StatusInternalServerError)
			return
		}
		// determine help level based on penalties
		if penalty > 0 && penalty <= smallHelpPenalty {
			help = 1
		} else if penalty > smallHelpPenalty {
			help = 2
		}

		// handle answer and help form submission
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Could not parse form", http.StatusBadRequest)
				return
			}
			if r.FormValue("help") == "1" && help == 0 { // small help
				help = 1
				db.Exec("INSERT INTO penalties (team_id, task_id, minutes) VALUES (?, ?, ?)", teamID, taskID, smallHelpPenalty)
				db.Exec("UPDATE teams SET penalty = penalty + ? WHERE id = ?", smallHelpPenalty, teamID)
			} else if r.FormValue("help") == "2" && help == 1 { // give up
				help = 2
				db.Exec("UPDATE penalties SET minutes = minutes + ? WHERE team_id = ? AND task_id = ?", giveUpPenalty, teamID, taskID)
				db.Exec("UPDATE teams SET penalty = penalty + ?, last_cipher = ? WHERE id = ?", giveUpPenalty, order+1, teamID)
			} else if answer := r.FormValue("solution"); answer != "" && help < 2 { // answer submission
				var correctAnswer string
				err = db.QueryRow("SELECT solution FROM CIPHERS WHERE id = ?", cipherID).Scan(&correctAnswer)
				if err != nil {
					http.Error(w, "Could not retrieve solution", http.StatusInternalServerError)
					return
				}
				if strings.EqualFold(strings.TrimSpace(answer), strings.TrimSpace(correctAnswer)) {
					// correct answer, move to next task
					db.Exec("UPDATE teams SET last_cipher = ? WHERE id = ?", order+1, teamID)
					help = 2
				} else {
					CipherTemplateData.Wrong = true
				}
			}
		}

		// find which clues to show
		switch help {
		case 1: // small help
			var helpText string
			err = db.QueryRow("SELECT clue FROM CIPHERS WHERE id = ?", cipherID).Scan(&helpText)
			if err == sql.ErrNoRows {
				helpText = ""
			} else if err != nil {
				http.Error(w, "Could not retrieve help text", http.StatusInternalServerError)
				return
			}
			CipherTemplateData.HelpText = helpText
		case 2: // next cipher
			// get end clue
			var endClue string
			err = db.QueryRow("SELECT end_clue FROM TASKS WHERE id = ?", taskID).Scan(&endClue)
			if err == sql.ErrNoRows {
				endClue = ""
			} else if err != nil {
				http.Error(w, "Could not retrieve end clue", http.StatusInternalServerError)
				return
			}
			CipherTemplateData.FinalClue = endClue
			// get coordinates
			var coordinates, positionHint string
			err = db.QueryRow("SELECT gps, clue FROM POSITIONS WHERE id = (SELECT position_id FROM TASKS WHERE id = (SELECT id FROM TASKS WHERE order_num = ? AND difficulty_level = (SELECT difficulty_level FROM teams WHERE id = ?)))", order+1, teamID).Scan(&coordinates, &positionHint)
			if err == sql.ErrNoRows {
				coordinates = "Konec, vraťte se."
				positionHint = "KONEC"
			} else if err != nil {
				http.Error(w, "Could not retrieve coordinates", http.StatusInternalServerError)
				return
			}
			CipherTemplateData.Coordinates = coordinates
			CipherTemplateData.PositionHint = positionHint
			// get solution
			var solution string
			err = db.QueryRow("SELECT solution FROM CIPHERS WHERE id = ?", cipherID).Scan(&solution)
			if err == sql.ErrNoRows {
				solution = ""
			} else if err != nil {
				http.Error(w, "Could not retrieve solution", http.StatusInternalServerError)
				return
			}
			CipherTemplateData.Solution = solution
		}

		CipherTemplateData.Help = help
		err = CipherTemplate.Execute(w, CipherTemplateData)
		if err != nil {
			http.Error(w, "Could not render template", http.StatusInternalServerError)
			return
		}
	}
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", dbFile+"?_fk=on")
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// klice app
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/team", teamInfoHandler)
	http.HandleFunc("/qr/", qrHandler)
	// admin app
	http.HandleFunc("/admin/login", adminLoginHandler)
	http.HandleFunc("/admin/logout", adminLogoutHandler)
	http.HandleFunc("/admin/", adminHandler)
	http.HandleFunc("/admin/teams", adminTeamsHandler)
	http.HandleFunc("/admin/start", AdminStartHandler)
	http.HandleFunc("/admin/routes", AdminRouteHandler)
	http.HandleFunc("/admin/levels", AdminLevelHandler)
	http.HandleFunc("/admin/cipher", AdminCipherHandler)
	http.HandleFunc("/admin/positions", AdminPositionsHandler)
	http.HandleFunc("/admin/qr/{qr...}", AdminQRHandler)
	http.HandleFunc("/admin/penalties", AdminPenaltiesHandler)

	// static files
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}
