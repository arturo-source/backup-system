package main

import (
	"encoding/base64"
	"math/rand"
	"time"
)

//Only readable characters to avoid problems with json
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

//RandStringBytes generates random readable array of bytes to be used as salt
func RandStringBytes(n int) []byte {
	rand.Seed(time.Now().UTC().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
