package main

import (
	"html/template"
)

type CipherTemplateS struct {
	ID           int
	Order        uint
	Assignment   template.HTML
	HelpText     string
	FinalClue    string
	Coordinates  string
	PositionHint string
	Solution     string
	Help         int
	Wrong        bool
}

type TeamTemplateS struct {
	TeamName   string
	Difficulty string
	LastCipher int
	Penalties  int
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
	Clue       string
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

var CipherTemplate = template.Must(template.ParseFiles("templates/assignment.html"))
var TeamTemplate = template.Must(template.ParseFiles("templates/team.html"))
var AdminTeamsTemplate = template.Must(template.ParseFiles("templates/adminTeams.html"))
var AdminRoutesTemplate = template.Must(template.ParseFiles("templates/adminRoutes.html"))
var AdminLevelTemplate = template.Must(template.ParseFiles("templates/adminLevels.html"))
var AdminCipherTemplate = template.Must(template.ParseFiles("templates/adminCiphers.html"))
var AdminPositionsTemplate = template.Must(template.ParseFiles("templates/adminPositions.html"))
var AdminQRsTemplate = template.Must(template.ParseFiles("templates/adminQR.html"))
