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

type AdminRoutesTemplateS struct {
	Name    string
	Ciphers []CipherTemplateS
}

var CipherTemplate = template.Must(template.ParseFiles("templates/assignment.html"))
var TeamTemplate = template.Must(template.ParseFiles("templates/team.html"))
var AdminTeamsTemplate = template.Must(template.ParseFiles("templates/adminTeams.html"))
var AdminRoutesTemplate = template.Must(template.ParseFiles("templates/adminRoutes.html"))
