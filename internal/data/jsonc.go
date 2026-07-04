package data

import (
	"bytes"
	"encoding/json"
	"os"
)

func LoadJSONC(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	clean := removeTrailingCommas(StripJSONC(raw))
	var out map[string]any
	if err := json.Unmarshal(clean, &out); err != nil {
		return nil, err
	}
	deleteGenerated(out)
	return out, nil
}

func StripJSONC(in []byte) []byte {
	var out bytes.Buffer
	inString := false
	escaped := false
	for i := 0; i < len(in); i++ {
		ch := in[i]
		if inString {
			out.WriteByte(ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			out.WriteByte(ch)
			continue
		}
		if ch == '/' && i+1 < len(in) {
			switch in[i+1] {
			case '/':
				i += 2
				for i < len(in) && in[i] != '\n' && in[i] != '\r' {
					i++
				}
				if i < len(in) {
					out.WriteByte(in[i])
				}
				continue
			case '*':
				i += 2
				for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
					if in[i] == '\n' || in[i] == '\r' {
						out.WriteByte(in[i])
					}
					i++
				}
				i++
				continue
			}
		}
		out.WriteByte(ch)
	}
	return out.Bytes()
}

func removeTrailingCommas(in []byte) []byte {
	var out bytes.Buffer
	inString := false
	escaped := false
	for i := 0; i < len(in); i++ {
		ch := in[i]
		if inString {
			out.WriteByte(ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			out.WriteByte(ch)
			continue
		}
		if ch == ',' {
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\r' || in[j] == '\n') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue
			}
		}
		out.WriteByte(ch)
	}
	return out.Bytes()
}

func deleteGenerated(m map[string]any) {
	for _, key := range []string{"ret", "time", "msg", "request_id"} {
		delete(m, key)
	}
}
