package main

import (
	"crypto/sha256"
	"fmt"
)

type user struct {
	username                  string
	password                  string
	passwordLogInServerHassed []byte
	cipherKey                 []byte
}

func (u *user) Hash(password string) {
	hash := sha256.New()
	_, err := hash.Write([]byte(u.password))
	if err != nil {
		panic(err)
	}
	passwordHashed := hash.Sum(nil)

	u.cipherKey = passwordHashed[:16]
	u.passwordLogInServerHassed = passwordHashed[16:]
}

func (u *user) SignIn(username, password string) {
	u.username = username
	u.password = password

	fmt.Printf("Username: %s\nPassword: %s", username, password)
}

func (u *user) SignUp(username, password string) {
	u.username = username
	u.password = password

	fmt.Printf("Username: %s\nPassword: %s", username, password)
}

func (u *user) EncryptFile(content []byte) {
	// cipher, err := aes.NewCipher(u.cipherKey)
	// if err != nil {
	// 	panic(err)
	// }

	// TO DO
}

func (u *user) SendToServer(content []byte) {
	//TO DO
}
