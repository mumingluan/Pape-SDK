package store

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
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

func randInt63n(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		panic(err)
	}
	return v.Int64()
}
