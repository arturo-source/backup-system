package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

type user struct {
	Username       string `json:"name"`
	PasswordHashed []byte `json:"pass"`
}

const backUpPath string = "backups/"

func (u *user) Hash(password, salt []byte) {
	hash := sha256.New()
	_, err := hash.Write(password)
	if err != nil {
		panic(err)
	}
	u.PasswordHashed = hash.Sum(nil)
}

func (u *user) CompareHash(passwordToCompare []byte) bool {
	hash := sha256.New()
	_, err := hash.Write(passwordToCompare)
	if err != nil {
		panic(err)
	}
	passwordHashed := hash.Sum(nil)

	return bytes.Compare(u.PasswordHashed, passwordHashed) == 0
}

//EncryptContent recieves an array of bytes and returns the same but encrypted
func (u *user) EncryptContent(content []byte) ([]byte, error) {
	//Creates the cipher
	c, err := aes.NewCipher(u.PasswordHashed)
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

//DecryptContent recieves an array of bytes encrypted and returns the same but decrypted
func (u *user) DecryptContent(content []byte) ([]byte, error) {
	//Creates the cipher
	c, err := aes.NewCipher(u.PasswordHashed)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(content) < nonceSize {
		return nil, fmt.Errorf("Error: the encrypted content doens't correspond to this key because it's too small")
	}
	//Get the content without nonce and decrypt that
	nonce, content := content[:nonceSize], content[nonceSize:]
	decryptedContent, err := gcm.Open(nil, nonce, content, nil)
	if err != nil {
		return nil, err
	}

	return decryptedContent, nil
}

// Group of users registered on the server
var users map[string]user

//The admin to control th server
var admin user

// Response type to comunicate with the client
type resp struct {
	Ok  bool
	Msg string
}

// Fill the struct and send the response
func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}
	rJSON, err := json.Marshal(&r)
	if err != nil {
		panic(err)
	}
	w.Write(rJSON)
}

func main() {
	admin = user{Username: "admin"}
	fmt.Println("Enter admin password: ")
	//Take the password without showing it, more secure
	adminPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	admin.Hash(adminPassword)

	data, err := ioutil.ReadFile("bbdd")
	if err != nil {
		panic(err)
	}
	users = make(map[string]user)

	// If the db is empty, then you don't have to Unmarshal
	// Because it causes error
	if len(data) > 0 {
		decryptedData, err := admin.DecryptContent(data)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(decryptedData, &users)
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("Password accepted")

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/backup", backupHandler)

	err = http.ListenAndServeTLS(":9043", "certificates/server.crt", "certificates/server.key", nil)
	if err != nil {
		panic(err)
	}
}

// Response "User has been registered" if register have been possible
func registerHandler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	u := user{}
	u.Username = req.Form.Get("username")
	password, err := base64.StdEncoding.DecodeString(req.Form.Get("passwd"))
	if err != nil {
		panic(err)
	}

	u.Hash(password)

	_, ok := users[u.Username] // Is the user in the db?
	if ok {
		response(w, false, "User is already registered")
	} else {
		users[u.Username] = u
		// Parsing the map to array of bytes
		uJSON, err := json.Marshal(users)
		if err != nil {
			panic(err)
		}
		// Encrypt the users before saving them
		encryptedUsers, err := admin.EncryptContent(uJSON)
		if err != nil {
			panic(err)
		}

		// This array of bytes is written in the db
		err = ioutil.WriteFile("bbdd", encryptedUsers, 0644)
		if err != nil {
			panic(err)
		}
		response(w, true, "User has been registered")
	}
}

// Response "Valid credentials" if data is Ok
// Other cases are not Ok
func loginHandler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	u, ok := users[req.Form.Get("username")] // Is the user in the db?
	if ok {
		password, err := base64.StdEncoding.DecodeString(req.Form.Get("passwd"))
		if err != nil {
			panic(err)
		}
		if u.CompareHash(password) { // The password hashed match
			response(w, true, "Valid credentials")
		} else {
			response(w, false, "Invalid credentials")
		}
	} else {
		response(w, false, "The user doesn't exist")
	}
}

// Return a string which is the username directory and true if the password is from the user
func isValidUser(req *http.Request) (string, bool) {
	u, ok := users[req.Header.Get("username")] // Is the user in the db?
	if ok {
		password, err := base64.StdEncoding.DecodeString(req.Header.Get("passwd"))
		if err != nil {
			panic(err)
		}
		if u.CompareHash(password) { // The password hashed match
			return u.Username + "/", true
		}
	}
	return "", false
}

// Creates the directory if it doesn't exists
func checkMkdir(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.Mkdir(path, 0755)
	}
}

func backupHandler(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			fmt.Println(err)
		}
		if len(body) > 0 {
			// If the user is valid, then response the content of the backup
			if u, ok := isValidUser(req); ok {
				//Read the content of the file
				content, err := ioutil.ReadFile(backUpPath + u + string(body))
				if err != nil { //Response "backup not found" to client when there isn't file?
					fmt.Println(err)
				} else {
					w.Write(content)
				}
			}
		} else {
			// If the user is valid, then list the content of the backups and response
			if u, ok := isValidUser(req); ok {
				content := ""
				checkMkdir(backUpPath + u)
				file, err := os.Open(backUpPath + u)
				if err != nil {
					fmt.Printf("failed opening directory: %s\n", err)
				}
				defer file.Close()

				list, _ := file.Readdirnames(0) // 0 to read all files and folders
				for _, name := range list {
					content += name + ","
				}
				contentLen := len(content)
				if contentLen > 0 {
					content = content[:contentLen-1]
				}
				response(w, true, content)
			}
		}

	case http.MethodPost:
		checkMkdir(backUpPath)
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			response(w, false, "The file is empty")
		} else {
			// If the user is valid, then can save files in its directory
			if u, ok := isValidUser(req); ok {
				checkMkdir(backUpPath + u)
				//Write the content on the file
				err = ioutil.WriteFile(backUpPath+u+time.Now().String(), body, 0644)
				if err != nil {
					fmt.Println(err)
				}
				response(w, true, "File saved")
			}
		}
	}
}
