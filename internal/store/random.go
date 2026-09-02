package store

import (
	"crypto/rand"
	"encoding/hex"
)

func makeToken(prefix string) string {
	return prefix + "_" + randomHex(20)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
