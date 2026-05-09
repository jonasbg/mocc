package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiDim   = "\033[2m"

	colorBlue    = "\033[38;5;39m"
	colorGreen   = "\033[38;5;71m"
	colorMagenta = "\033[38;5;171m"
	colorCyan    = "\033[38;5;44m"
	colorYellow  = "\033[38;5;221m"
	colorRed     = "\033[38;5;203m"
	colorGray    = "\033[38;5;246m"
)

type logDetailStyle struct {
	key   string
	value string
}

var (
	defaultDetailStyle = logDetailStyle{key: ansiBold + colorGray, value: colorGray}
	locationStyle      = logDetailStyle{key: ansiBold + colorCyan, value: colorCyan}
	detailPalette      = map[string]logDetailStyle{
		"response_type":         {key: ansiBold + colorCyan, value: colorCyan},
		"client_id":             {key: ansiBold + colorMagenta, value: colorMagenta},
		"redirect_uri":          {key: ansiBold + colorGreen, value: colorGreen},
		"scope":                 {key: ansiBold + colorYellow, value: colorYellow},
		"state":                 {key: ansiBold + colorBlue, value: colorBlue},
		"nonce":                 {key: ansiBold + colorCyan, value: colorCyan},
		"code_challenge":        {key: ansiBold + colorMagenta, value: colorMagenta},
		"code_challenge_method": {key: ansiBold + colorGray, value: colorGray},
		"grant_type":            {key: ansiBold + colorYellow, value: colorYellow},
		"code":                  {key: ansiBold + colorBlue, value: colorBlue},
		"code_verifier":         {key: ansiBold + colorGreen, value: colorGreen},
	}
)

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if shouldSkipRequestLog(path) {
			return
		}
		c.Next()

		method := c.Request.Method
		status := c.Writer.Status()
		details := requestLogDetails(c)

		methodStr := wrapColor(method, colorForMethod(method))
		pathStr := wrapColor(path, ansiDim+colorGray)
		statusStr := wrapColor(fmt.Sprintf("%d", status), colorForStatus(status))

		msg := fmt.Sprintf("%s %s -> %s", methodStr, pathStr, statusStr)
		if len(details) > 0 {
			msg = fmt.Sprintf("%s [%s]", msg, strings.Join(details, " "))
		}

		log.Println(msg)
	}
}

func shouldSkipRequestLog(path string) bool {
	if path == "/" {
		return true
	}
	for _, prefix := range []string{"/static/", "/favicon"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func requestLogDetails(c *gin.Context) []string {
	details := make([]string, 0)
	for key, values := range c.Request.URL.Query() {
		for _, val := range values {
			details = append(details, formatDetail(key, truncateDisplay(val, 60)))
		}
	}

	if c.Request.Method == http.MethodPost {
		_ = c.Request.ParseForm()
		for key, values := range c.Request.PostForm {
			for _, val := range values {
				details = append(details, formatDetail(key, truncateDisplay(val, 60)))
			}
		}
	}

	if loc := c.Writer.Header().Get("Location"); loc != "" {
		details = append(details, formatDetail("location", truncateDisplay(loc, 80)))
	}
	return details
}

func wrapColor(text, color string) string {
	if color == "" {
		return text
	}
	return color + text + ansiReset
}

func formatDetail(key, value string) string {
	style, ok := detailPalette[key]
	if !ok {
		if key == "location" {
			style = locationStyle
		} else {
			style = defaultDetailStyle
		}
	}
	return fmt.Sprintf("%s%s%s=%s%s%s", style.key, key, ansiReset, style.value, value, ansiReset)
}

func colorForMethod(method string) string {
	switch method {
	case http.MethodGet:
		return ansiBold + colorCyan
	case http.MethodPost:
		return ansiBold + colorMagenta
	case http.MethodPut, http.MethodPatch:
		return ansiBold + colorYellow
	case http.MethodDelete:
		return ansiBold + colorRed
	default:
		return ansiBold + colorGray
	}
}

func colorForStatus(status int) string {
	switch {
	case status >= 500:
		return ansiBold + colorRed
	case status >= 400:
		return ansiBold + colorYellow
	case status >= 300:
		return ansiBold + colorCyan
	default:
		return ansiBold + colorGreen
	}
}

func truncateDisplay(val string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(val)
	if len(runes) <= limit {
		return val
	}
	if limit == 1 {
		return string(runes[0])
	}
	return string(runes[:limit-1]) + "…"
}
