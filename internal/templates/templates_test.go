package templates_test

import (
	"bytes"
	"strings"
	"testing"

	"mocc/internal/templates"
)

// TestLoadTemplates ensures embedded templates parse and render without error.
func TestLoadTemplates(t *testing.T) {
	tm := templates.LoadTemplates()
	if tm == nil {
		t.Fatal("templates map is nil")
	}
	tindex, ok := tm["index.html"]
	if !ok {
		t.Fatalf("index.html not found in templates map: keys=%v", func() []string {
			ks := make([]string, 0, len(tm))
			for k := range tm {
				ks = append(ks, k)
			}
			return ks
		}())
	}
	var buf bytes.Buffer
	if err := tindex.ExecuteTemplate(&buf, "layout.html", map[string]interface{}{"Users": []interface{}{}}); err != nil {
		t.Fatalf("failed to execute template: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "mocc") {
		t.Fatalf("rendered output missing expected content, got: %q", out)
	}
}
