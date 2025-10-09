package main

import (
	"html/template"
)

type CipherTemplateS struct {
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

type AdminRoutesTemplateS struct {
	Name    string
	Ciphers []CipherTemplateS
}

type AdminCipherTemplateS struct {
	ID         int
	Assignment string
	Solution   string
	Clue       string
}

var CipherTemplate = template.Must(template.ParseFiles("templates/assignment.html"))
var TeamTemplate = template.Must(template.ParseFiles("templates/team.html"))
var AdminTeamsTemplate = template.Must(template.ParseFiles("templates/adminTeams.html"))
var AdminRoutesTemplate = template.Must(template.ParseFiles("templates/adminRoutes.html"))
var AdminLevelTemplate = template.Must(template.ParseFiles("templates/adminLevels.html"))
var AdminCipherTemplate = template.Must(template.ParseFiles("templates/adminCiphers.html"))
