package env

import (
	"os"
	"strconv"
)

func GetBool(key string, def bool) bool {
	if env := os.Getenv(key); env != "" {
		if b, err := strconv.ParseBool(env); err == nil {
			return b
		}
	}
	return def
}

func GetInt(key string, def int) int {
	if env := os.Getenv(key); env != "" {
		if i, err := strconv.Atoi(env); err == nil {
			return i
		}
	}
	return def
}

func GetString(key, def string) string {
	if env := os.Getenv(key); env != "" {
		return env
	}
	return def
}
