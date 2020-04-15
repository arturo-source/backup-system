package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

//Only readable characters to avoid problems with json
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

//RandStringBytes generates random readable array of bytes to be used as salt
func RandStringBytes() []byte {
	rand.Seed(time.Now().UTC().UnixNano())
	b := make([]byte, 10)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

//Const directory where back ups are saved
const backUpPath string = "backups/"

//Variable to control the tokens
var tokens Tokens

// Group of users registered on the server
var users map[string]user

//The admin to control the server
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
	tokens = Tokens{
		tokens: make([]Token, 0),
	}
	//A goroutine to delete expired tokens each hour
	go func() {
		for {
			time.Sleep(time.Hour)
			tokens.DeleteExpireds()
		}
	}()

	admin = user{Username: "admin"}
	fmt.Println("Enter admin password: ")
	//Take the password without showing it, more secure
	adminPassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}
	admin.Hash(adminPassword, nil)

	data, err := ioutil.ReadFile("bbdd")
	if err != nil {
		panic(err)
	}
	users = make(map[string]user)

	// If the db is empty, then you don't have to Unmarshal
	// or decrypt it because it causes error
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

	u.Hash(password, RandStringBytes())

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
		tokens.Add(u.Username)
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
			tokens.Add(u.Username)
			response(w, true, "Valid credentials")
		} else {
			response(w, false, "Invalid credentials")
		}
	} else {
		response(w, false, "The user doesn't exist")
	}
}

// THIS METHOD IS DEPRECATED BECAUSE NOW WE USE TOKENS
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
	token := req.Header.Get("token")
	if _, exists := tokens.Exists(token); exists {
		switch req.Method {
		case http.MethodGet:
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				fmt.Println(err)
			}
			//The content of the body is the back up name so response the content of the backup
			if len(body) > 0 {
				u := tokens.Owner(token) + "/"
				//Read the content of the file
				content, err := ioutil.ReadFile(backUpPath + u + string(body))
				if err != nil {
					response(w, false, "Back up not found")
					fmt.Println(err)
				} else {
					w.Write(content)
				}
			} else { //If the body is empty: list the content of the backups and response
				u := tokens.Owner(token) + "/"
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

		case http.MethodPost:
			checkMkdir(backUpPath)
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				response(w, false, "The file is empty")
			} else {
				u := tokens.Owner(token) + "/"
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
