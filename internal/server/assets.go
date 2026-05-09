package server

import (
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"mocc/internal/templates"
)

const embeddedStaticRoot = "assets/static/"

var devStaticRoots = []string{
	"internal/templates/assets/static",
}

func (s *Server) handleStatic(c *gin.Context) {
	name, ok := cleanStaticName(c.Param("any"))
	if !ok {
		c.String(http.StatusNotFound, "")
		return
	}

	if data, ok, err := readEmbeddedStatic(name); err != nil {
		c.String(http.StatusInternalServerError, "failed to read static asset")
		return
	} else if ok {
		c.Data(http.StatusOK, contentType(name, data), data)
		return
	}

	if data, ok, err := readDevStatic(name); err != nil {
		c.String(http.StatusInternalServerError, "failed to read static asset")
		return
	} else if ok {
		c.Data(http.StatusOK, contentType(name, data), data)
		return
	}

	c.Status(http.StatusNotFound)
}

func cleanStaticName(raw string) (string, bool) {
	raw = strings.TrimPrefix(raw, "/")
	if raw == "" {
		return "", false
	}
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			return "", false
		}
	}
	name := path.Clean("/" + raw)
	if name == "/" {
		return "", false
	}
	return strings.TrimPrefix(name, "/"), true
}

func readEmbeddedStatic(name string) ([]byte, bool, error) {
	f, err := templates.TemplatesFS.Open(embeddedStaticRoot + name)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	return data, err == nil, err
}

func readDevStatic(name string) ([]byte, bool, error) {
	for _, root := range devStaticRoots {
		data, err := os.ReadFile(filepath.Join(root, name))
		if os.IsNotExist(err) {
			continue
		}
		return data, err == nil, err
	}
	return nil, false, nil
}

func contentType(name string, data []byte) string {
	if ext := filepath.Ext(name); ext != "" {
		if contentType := mime.TypeByExtension(ext); contentType != "" {
			return contentType
		}
	}
	return http.DetectContentType(data)
}
