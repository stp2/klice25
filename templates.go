package main

import (
	"embed"
	"html/template"
)

//go:embed templates/*.html
var templatesFS embed.FS

type CipherTemplateS struct {
	ID           int
	Order        uint
	Assignment   template.HTML
	HelpText     template.HTML
	FinalClue    string
	Coordinates  string
	PositionHint string
	Solution     string
	Help         int
	Wrong        bool
	URL          string
}

type TeamTemplateS struct {
	ID               int
	TeamName         string
	Difficulty       string
	LastCipher       int
	LastLoadedCipher int
	Penalties        int
}

type DifficultyLevelS struct {
	ID   int
	Name string
}

type TeamsTemplateS struct {
	Teams        []TeamTemplateS
	Difficulties []DifficultyLevelS
}

type AdminRouteTemplateS struct {
	Name    string
	Ciphers []CipherTemplateS
}

type AdminRoutesTemplateS struct {
	Routes    []AdminRouteTemplateS
	Levels    []int
	Positions []int
	Ciphers   []int
}

type AdminCipherTemplateS struct {
	ID         int
	Assignment template.HTML
	Solution   string
	Clue       template.HTML
}

type AdminPositionsTemplateS struct {
	ID   int
	GPS  string
	Clue string
	URL  string
}

type AdminQRsTemplateS struct {
	URL      string
	Position string
	GPS      string
	ID       int
}

type AdminQRTemplateS struct {
	QRs       []AdminQRsTemplateS
	Positions []int
}

type AdminLevelTemplateS struct {
	ID   int
	Name string
}

type AdminPenaltiesTemplateS struct {
	TeamName  string
	TaskOrder uint
	Minutes   int
}

var CipherTemplate = template.Must(template.ParseFS(templatesFS, "templates/assignment.html"))
var TeamTemplate = template.Must(template.ParseFS(templatesFS, "templates/team.html"))
var AdminTeamsTemplate = template.Must(template.ParseFS(templatesFS, "templates/adminTeams.html"))
var AdminRoutesTemplate = template.Must(template.ParseFS(templatesFS, "templates/adminRoutes.html"))
var AdminLevelTemplate = template.Must(template.ParseFS(templatesFS, "templates/adminLevels.html"))
var AdminCipherTemplate = template.Must(template.ParseFS(templatesFS, "templates/adminCiphers.html"))
var AdminPositionsTemplate = template.Must(template.ParseFS(templatesFS, "templates/adminPositions.html"))
var AdminQRsTemplate = template.Must(template.ParseFS(templatesFS, "templates/adminQR.html"))
var AdminPenaltiesTemplate = template.Must(template.ParseFS(templatesFS, "templates/adminPenalties.html"))
