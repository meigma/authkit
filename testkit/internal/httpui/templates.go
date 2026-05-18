package httpui

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"time"
)

const (
	layoutTemplate = "templates/layout.html"
	pageTemplate   = "content"
	timeFormat     = "2006-01-02 15:04 UTC"
)

//go:embed templates/*.html static/*.css
var content embed.FS

type templateSet struct {
	pages map[string]*template.Template
}

func newTemplateSet() (*templateSet, error) {
	pageFiles := map[string]string{
		pageEdit:  "templates/edit.html",
		pageError: "templates/error.html",
		pageIndex: "templates/index.html",
		pageLogin: "templates/login.html",
		pageNew:   "templates/new.html",
		pagePaste: "templates/paste.html",
	}
	pages := make(map[string]*template.Template, len(pageFiles))
	funcs := template.FuncMap{
		"formatTime": formatTime,
	}

	for name, file := range pageFiles {
		parsed, err := template.New(name).Funcs(funcs).ParseFS(content, layoutTemplate, file)
		if err != nil {
			return nil, fmt.Errorf("httpui: parse template %s: %w", name, err)
		}
		pages[name] = parsed
	}

	return &templateSet{pages: pages}, nil
}

func (t *templateSet) execute(w io.Writer, page string, data pageData) error {
	tmpl, exists := t.pages[page]
	if !exists {
		return fmt.Errorf("httpui: template %s not found", page)
	}
	if err := tmpl.ExecuteTemplate(w, pageTemplate, data); err != nil {
		return fmt.Errorf("httpui: execute template %s: %w", page, err)
	}

	return nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(timeFormat)
}
