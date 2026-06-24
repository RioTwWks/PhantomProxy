package ui

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed templates/*.html templates/partials/*.html static/*
var content embed.FS

// Templates возвращает FS с HTML-шаблонами.
func Templates() fs.FS {
	sub, err := fs.Sub(content, "templates")
	if err != nil {
		panic(err)
	}
	return sub
}

// Static возвращает FS со статикой.
func Static() fs.FS {
	sub, err := fs.Sub(content, "static")
	if err != nil {
		panic(err)
	}
	return sub
}

// ParseTemplates парсит все шаблоны (без funcs — funcs добавляются в NewHandler).
func ParseTemplates() *template.Template {
	return template.Must(template.ParseFS(Templates(), "*.html", "partials/*.html"))
}
