package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Handle login logic here
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Could not parse form", http.StatusBadRequest)
			return
		}
		password := r.FormValue("password")
		hashedPassword := hashPassword(password)
		var teamID int

		err := db.QueryRow("SELECT id FROM teams WHERE password = ?", hashedPassword).Scan(&teamID)
		if err == sql.ErrNoRows {
			http.Error(w, "No team found", http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, "Could not retrieve team", http.StatusInternalServerError)
			return
		}

		var sessionID string
		sessionID = hashedPassword
		cookie := &http.Cookie{
			Name:  "session_id",
			Value: sessionID,
			Path:  "/",
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
	} else if r.Method == http.MethodGet {
		loginPage, err := os.Open("login.html")
		if err != nil {
			http.Error(w, "Could not open login page", http.StatusInternalServerError)
			return
		}
		defer loginPage.Close()

		io.Copy(w, loginPage)
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
		var teamName, city string
		err := db.QueryRow("SELECT name, city FROM teams WHERE id = ?", teamID).Scan(&teamName, &city)
		if err != nil {
			http.Error(w, "Could not retrieve team information", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Team Name: %s, City: %s", teamName, city)
	}
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./klice.db?_fk=on")
	if err != nil {
		fmt.Println("Error opening database:", err)
		return
	}
	defer db.Close()

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/team", teamInfoHandler)

	fmt.Println("Server started at :8080")
	http.ListenAndServe(":8080", nil)
}
