package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

type user struct {
	username                  string
	passwordLogInServerHassed []byte
	cipherKey                 []byte
}

func (u *user) Hash(password string) {
	hash := sha256.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		panic(err)
	}
	passwordHashed := hash.Sum(nil)

	u.cipherKey = passwordHashed[:16]
	u.passwordLogInServerHassed = passwordHashed[16:]
}

func (u *user) SignIn(username, password string) {
	u.username = username
	u.Hash(password)

	u.SendToServer("login")

	//TODO: Check if the user exists in the server db
}

func (u *user) SignUp(username, password string) {
	u.username = username
	u.Hash(password)

	u.SendToServer("register")

	//TODO: Create the user in the server db and check if its done Ok
}

func (u *user) EncryptFile(content []byte) ([]byte, error) {
	c, err := aes.NewCipher(u.cipherKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	//Seal the content to be retorned encrypted
	encryptedContent := gcm.Seal(nonce, nonce, content, nil)

	return encryptedContent, nil
}

func (u *user) DecryptFile(content []byte) ([]byte, error) {
	c, err := aes.NewCipher(u.cipherKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(content) < nonceSize {
		return nil, fmt.Errorf("Error: the encrypted content doens't correspond to this key because is too small")
	}
	//Get the content without nonce and decrypt that
	nonce, content := content[:nonceSize], content[nonceSize:]
	decryptedContent, err := gcm.Open(nil, nonce, content, nil)
	if err != nil {
		return nil, err
	}

	return decryptedContent, nil
}

//SendToServer returns an error if there is an error and true if the message arrived well
func (u *user) SendToServer(comand string) error {
	data := url.Values{}
	data.Set("comand", comand)
	data.Set("username", u.username)
	data.Set("passwd", string(u.passwordLogInServerHassed))

	// Not verifying the credentials because they are autosigned
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	r, err := client.PostForm("https://localhost:10443", data)
	if err != nil {
		return err
	}
	io.Copy(os.Stdout, r.Body)
	fmt.Println()

	//TODO: Check if the comunication has done Ok and return that

	return nil
}
