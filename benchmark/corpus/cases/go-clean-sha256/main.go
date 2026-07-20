package main

import "crypto/sha256"

func f() []byte {
	h := sha256.New()
	return h.Sum(nil)
}
