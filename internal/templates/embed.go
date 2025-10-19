package templates

import (
	"embed"
)

//go:embed assets/* assets/*/*
var TemplatesFS embed.FS
