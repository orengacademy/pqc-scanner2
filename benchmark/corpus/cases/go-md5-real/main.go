package main

import "crypto/md5"

func f() []byte {
	h := md5.New()
	return h.Sum(nil)
}
