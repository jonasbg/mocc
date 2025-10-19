package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type User struct {
	Sub      string `yaml:"sub"`
	Name     string `yaml:"name"`
	Email    string `yaml:"email"`
	Initials string `yaml:"-"`
	Claims   map[string]interface{} `yaml:"claims"`
}

type Config struct {
	Users []User `yaml:"users"`
}

// LoadUsers reads users.yaml from the provided path and returns users.
func LoadUsers(path string) ([]User, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseUsers(data)
}

// LoadEmbeddedUsers returns the users from the embedded default users.yaml.
func LoadEmbeddedUsers() ([]User, error) {
	if len(defaultUsersYAML) == 0 {
		return nil, errors.New("embedded users configuration is empty")
	}
	return parseUsers(defaultUsersYAML)
}

// parseUsers unmarshals users.yaml data and applies normalization.
func parseUsers(data []byte) ([]User, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// Infer sub and compute initials
	for i := range cfg.Users {
		if cfg.Users[i].Sub == "" {
			cfg.Users[i].Sub = cfg.Users[i].Email
		}
		// compute initials
		name := cfg.Users[i].Name
		cfg.Users[i].Initials = initials(name)
		cfg.Users[i].Claims = normalizeClaims(cfg.Users[i].Claims)
	}
	return cfg.Users, nil
}

// HasEmbeddedUsers reports whether an embedded users.yaml is present.
func HasEmbeddedUsers() bool {
	return len(defaultUsersYAML) > 0
}

// initials returns 1-2 uppercase characters representing the name.
func initials(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	parts := strings.Fields(name)
	firstRune := func(s string) string {
		r := []rune(s)
		if len(r) == 0 {
			return ""
		}
		return string(r[0])
	}
	if len(parts) == 1 {
		r := []rune(parts[0])
		if len(r) >= 2 {
			return strings.ToUpper(string(r[0:2]))
		}
		return strings.ToUpper(string(r[0]))
	}
	return strings.ToUpper(firstRune(parts[0]) + firstRune(parts[len(parts)-1]))
}

func normalizeClaims(input map[string]interface{}) map[string]interface{} {
	if input == nil {
		return nil
	}
	out := make(map[string]interface{}, len(input))
	for k, v := range input {
		out[k] = normalizeValue(v)
	}
	return out
}

func normalizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		res := make(map[string]interface{}, len(val))
		for k, inner := range val {
			res[k] = normalizeValue(inner)
		}
		return res
	case map[interface{}]interface{}:
		res := make(map[string]interface{}, len(val))
		for k, inner := range val {
			key := fmt.Sprintf("%v", k)
			res[key] = normalizeValue(inner)
		}
		return res
	case []interface{}:
		for i := range val {
			val[i] = normalizeValue(val[i])
		}
		return val
	default:
		return v
	}
}
