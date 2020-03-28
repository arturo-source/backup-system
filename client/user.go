package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

// Response type recieve from the server
type resp struct {
	Ok  bool
	Msg string
}

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

func (u *user) SignIn(username, password string) (resp, error) {
	u.username = username
	u.Hash(password)

	response, err := u.AuthorizeOnServer("login")
	if err != nil {
		return resp{}, err
	}
	return response, nil
}

func (u *user) SignUp(username, password string) (resp, error) {
	u.username = username
	u.Hash(password)

	response, err := u.AuthorizeOnServer("register")
	if err != nil {
		return resp{}, err
	}
	return response, nil
}

func (u *user) EncryptFile(filePath string) error {
	//Read the content of the file
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	//Creates the cipher
	c, err := aes.NewCipher(u.cipherKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	//Seal the content to be retorned encrypted
	encryptedContent := gcm.Seal(nonce, nonce, content, nil)

	//Write the content on the file
	err = ioutil.WriteFile(filePath, encryptedContent, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (u *user) DecryptFile(filePath string) error {
	//Read the content of the file
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	//Creates the cipher
	c, err := aes.NewCipher(u.cipherKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	if len(content) < nonceSize {
		return fmt.Errorf("Error: the encrypted content doens't correspond to this key because is too small")
	}
	//Get the content without nonce and decrypt that
	nonce, content := content[:nonceSize], content[nonceSize:]
	decryptedContent, err := gcm.Open(nil, nonce, content, nil)
	if err != nil {
		return err
	}

	//Write the content on the file
	err = ioutil.WriteFile(filePath, decryptedContent, 0644)
	if err != nil {
		return err
	}

	return nil
}

//AuthorizeOnServer returns an error if there is an error and true if the message arrived well
func (u *user) AuthorizeOnServer(comand string) (resp, error) {
	response := resp{}
	data := url.Values{}
	data.Set("username", u.username)
	//Because not normal bytes can produce error when HTTP comunications
	data.Set("passwd", base64.StdEncoding.EncodeToString(u.passwordLogInServerHassed))

	// Not verifying the credentials because they are autosigned
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	r, err := client.PostForm("https://localhost:9043/"+comand, data)
	if err != nil {
		return response, err
	}
	defer r.Body.Close()

	//Unmarshal the response to a resp struct
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return response, err
	}
	json.Unmarshal(body, &response)

	return response, nil
}

func (u *user) SendBackUpToServer(path string) (resp, error) {
	response := resp{}
	//Creates a temporar file to compress, encrypt and send to the server
	err := compressFile(path, "compressed.zip")
	if err != nil {
		return response, err
	}
	err = u.EncryptFile("compressed.zip")
	if err != nil {
		return response, err
	}
	//Read the content of the file
	content, err := ioutil.ReadFile("compressed.zip")
	if err != nil {
		return response, err
	}

	req, err := http.NewRequest("POST", "https://localhost:9043/backup", bytes.NewBuffer(content))
	// Not verifying the credentials because they are autosigned
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	//Unmarshal the response to a res struct
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	json.Unmarshal(body, &response)

	//Removes the temporary file
	err = os.Remove("compressed.zip")
	if err != nil {
		return response, err
	}
	return response, nil
}
func (u *user) RecoverBackUp(name string) (resp, error) {
	response := resp{}
	req, err := http.NewRequest("GET", "https://localhost:9043/backup", bytes.NewBuffer([]byte(name)))
	// Not verifying the credentials because they are autosigned
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	//Creates a temporar file to decrypt, uncompress and recover the files
	err = ioutil.WriteFile("recover.zip", body, 0644)
	if err != nil {
		return response, err
	}
	err = u.DecryptFile("recover.zip")
	if err != nil {
		return response, err
	}
	err = uncompressFile("recover.zip", "recover")
	if err != nil {
		return response, err
	}
	//Removes the temporary file
	err = os.Remove("recover.zip")
	if err != nil {
		return response, err
	}
	return resp{Ok: true, Msg: "Recovered ok."}, nil
}

func (u *user) ListFiles() (resp, error) {
	response := resp{}
	req, err := http.NewRequest("GET", "https://localhost:9043/backup", nil)
	// Not verifying the credentials because they are autosigned
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	//Unmarshal the response to a res struct
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	json.Unmarshal(body, &response)

	return response, nil
}
