package utils

import (
	"bytes"
	"os"
	"strings"
)

// CleanString clean the string
func CleanString(data []byte) string {
	nullPos := bytes.IndexByte(data, 0)
	if nullPos == -1 {
		return string(data)
	}
	return string(data[:nullPos])
}

// CleanProcessName clean the process name
func CleanProcessName(data []byte) string {
	str := strings.Map(func(r rune) rune {
		if r == 0 {
			return ' '
		}
		if r < 32 || r > 126 {
			return ' '
		}
		return r
	}, string(data))

	str = strings.TrimSpace(str)
	str = strings.ReplaceAll(str, "  ", " ")
	str = strings.ReplaceAll(str, "\\x00", "")
	str = strings.ReplaceAll(str, "\\x20", " ")

	return str
}

// CleanCommandArgs clean the command line arguments
func CleanCommandArgs(data []byte, size uint32) string {
	if size == 0 {
		return ""
	}
	argvBytes := bytes.ReplaceAll(data[:size], []byte{0}, []byte{' '})
	return strings.TrimSpace(string(argvBytes))
}

// GetHostname returns the hostname of the current machine
func GetHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	return hostname, nil
}
