package templates

import (
	"html/template"
	"io/fs"
	"log"
	"path/filepath"
)

// LoadTemplates parses embedded templates and returns a map of base filename -> *template.Template
func LoadTemplates() map[string]*template.Template {
	tmpl := make(map[string]*template.Template)
	// Walk embedded files under assets/templates
	fs.WalkDir(TemplatesFS, "assets/templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".html" {
			return nil
		}
		// Parse layout + this page
		t, err := template.ParseFS(TemplatesFS, "assets/templates/layout.html", path)
		if err != nil {
			log.Fatalf("failed to parse template %s: %v", path, err)
		}
		tmpl[filepath.Base(path)] = t
		return nil
	})
	return tmpl
}
