package main

import (
	"html/template"
)

type CipherTemplateS struct {
	Order       uint
	Assignment  template.HTML
	HelpText    string
	FinalClue   string
	Coordinates string
	Solution    string
	Help        int
	Wrong       bool
}

type TeamTemplateS struct {
	TeamName   string
	Difficulty string
	LastCipher int
	Penalties  int
}

var CipherTemplate = template.Must(template.ParseFiles("templates/assignment.html"))
var TeamTemplate = template.Must(template.ParseFiles("templates/team.html"))
