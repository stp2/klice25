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
}

var CipherTemplate = template.Must(template.ParseFiles("templates/assignment.html"))
