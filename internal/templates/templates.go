package templates

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"path/filepath"
	texttemplate "text/template"
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

// LoadSkillTemplate parses the embedded SKILL.md markdown template using text/template
// (html/template would escape the markdown). Exposes a `formatClaims` helper.
func LoadSkillTemplate() *texttemplate.Template {
	data, err := TemplatesFS.ReadFile("assets/templates/skill.md.tmpl")
	if err != nil {
		log.Fatalf("failed to read skill template: %v", err)
	}
	funcs := texttemplate.FuncMap{
		"formatClaims": func(claims map[string]interface{}) string {
			if len(claims) == 0 {
				return "—"
			}
			b, err := json.Marshal(claims)
			if err != nil {
				return "—"
			}
			return "`" + string(b) + "`"
		},
	}
	t, err := texttemplate.New("skill.md").Funcs(funcs).Parse(string(data))
	if err != nil {
		log.Fatalf("failed to parse skill template: %v", err)
	}
	return t
}
