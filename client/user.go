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

//user is used to log in the server, send and recover files, etc.
type user struct {
	username                        string
	passwordLogInServerHassed       []byte
	cipherKey                       []byte
	base64passwordLogInServerHassed string
	httpclient                      *http.Client
	token                           string
}

//Hash the password and save 50% to encrypt files or folders,
//and the other 50% to be used as a passwd to log in the server
func (u *user) Hash(password string) {
	hash := sha256.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		panic(err)
	}
	passwordHashed := hash.Sum(nil)

	u.cipherKey = passwordHashed[:16]
	u.passwordLogInServerHassed = passwordHashed[16:]
	//Because not normal bytes can produce error when HTTP comunications
	u.base64passwordLogInServerHassed = base64.StdEncoding.EncodeToString(u.passwordLogInServerHassed)
}

func (u *user) sign(username, password, command string) (resp, error) {
	u.username = username
	u.Hash(password)

	// Not verifying the credentials because they are autosigned
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	u.httpclient = &http.Client{Transport: tr}

	response, err := u.AuthorizeOnServer(command)
	if err != nil {
		return resp{Ok: false, Msg: "Error trying to " + command}, err
	}
	if response.Ok {
		u.token = response.Msg
	}
	return response, nil
}

//SignIn initializes the variables of user and tries to log in
func (u *user) SignIn(username, password string) (resp, error) {
	return u.sign(username, password, "login")
}

//SignUp is used to register the user
func (u *user) SignUp(username, password string) (resp, error) {
	return u.sign(username, password, "register")
}

//EncryptFile receives a filepath and write the same file but encrypted
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

//DecryptFile receives a filepath of a file encrypted and write the same file but decrypted
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
		return fmt.Errorf("Error: the encrypted content doens't correspond to this key because it's too small")
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

//AuthorizeOnServer returns an error if there is an error and
//a resp with true if the message arrived well
func (u *user) AuthorizeOnServer(command string) (resp, error) {
	response := resp{}
	data := url.Values{}
	data.Set("username", u.username)
	data.Set("passwd", u.base64passwordLogInServerHassed)

	r, err := u.httpclient.PostForm("https://localhost:9043/"+command, data)
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

//SendBackUpToServer sends a folder or file to the server
//but its previously compressed and encrypted
func (u *user) SendBackUpToServer(path string) (resp, error) {
	response := resp{}
	//Creates a temporary file to compress, encrypt and send to the server
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
	//To authorize the user
	req.Header.Add("token", u.token)

	res, err := u.httpclient.Do(req)
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

//RecoverBackUp receives the name (a date normaly) of what back up
//you want to recover and decrypt and uncompress the file after that
func (u *user) RecoverBackUp(name string) (resp, error) {
	response := resp{}
	req, err := http.NewRequest("GET", "https://localhost:9043/backup", bytes.NewBuffer([]byte(name)))
	//To authorize the user
	req.Header.Add("token", u.token)

	res, err := u.httpclient.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	//Creates a temporary file to decrypt, uncompress and recover the files
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

//ListFiles ask the server for the backups saved in the server from this user
func (u *user) ListFiles() (resp, error) {
	response := resp{}
	req, err := http.NewRequest("GET", "https://localhost:9043/backup", nil)
	//To authorize the user
	req.Header.Add("token", u.token)

	res, err := u.httpclient.Do(req)
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
