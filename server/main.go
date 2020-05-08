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
	"regexp"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
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

func saveDatabase() error {
	// Parsing the map to array of bytes
	uJSON, err := json.Marshal(users)
	if err != nil {
		return err
	}
	// Encrypt the users before saving them
	encryptedUsers, err := admin.EncryptContent(uJSON)
	if err != nil {
		return err
	}

	// This array of bytes is written in the db
	err = ioutil.WriteFile("bbdd", encryptedUsers, 0644)
	if err != nil {
		return err
	}
	return nil
}

//IsValidString returns true if the string has valid characters
func IsValidString(username string) bool {
	isValid, _ := regexp.MatchString("^[A-Za-z0-9]{6,32}$", username)
	return isValid
}

//Const directory where back ups are saved
const backUpPath string = "backups/"

//Variable to control the tokens
var tokens Tokens

// Group of users registered on the server
var users map[string]*user

//The admin to control the server
var admin user

// Response type to comunicate with the client
type resp struct {
	Ok        bool
	Msg       string
	UserToken string
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
	users = make(map[string]*user)

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
	http.HandleFunc("/share", shareHandler)
	http.HandleFunc("/keys", keysHandler)
	http.HandleFunc("/keyfile", keyfileHandler)

	err = http.ListenAndServeTLS(":9043", "certificates/server.crt", "certificates/server.key", nil)
	if err != nil {
		panic(err)
	}
}

// Response a new token if register have been possible
func registerHandler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	u := &user{
		Username:          req.Form.Get("username"),
		PubKey:            req.Form.Get("pubkey"),
		PrivKey:           req.Form.Get("privkey"),
		Files:             make([]file, 0),
		SharedFilesWithMe: make([]file, 0),
	}
	if IsValidString(u.Username) {
		password, err := base64.StdEncoding.DecodeString(req.Form.Get("passwd"))
		if err != nil {
			fmt.Println(err)
		}

		u.Hash(password, RandStringBytes(10))

		_, ok := users[u.Username] // Is the user in the db?
		if ok {
			response(w, false, "User is already registered")
		} else {
			users[u.Username] = u

			err := saveDatabase()
			if err != nil {
				fmt.Println(err)
			}

			token := tokens.Add(u.Username)
			response(w, true, token)
		}
	} else {
		response(w, false, "Not valid username, use alphanumeric characters only.")
	}
}

// Response a new token if data is Ok
// Other cases are not Ok
func loginHandler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	username := req.Form.Get("username")
	if IsValidString(username) {
		u, ok := users[username] // Is the user in the db?
		if ok {
			password, err := base64.StdEncoding.DecodeString(req.Form.Get("passwd"))
			if err != nil {
				fmt.Println(err)
			}
			if u.CompareHash(password) { // The password hashed match
				token := tokens.Add(u.Username)
				response(w, true, token)
			} else {
				response(w, false, "Invalid credentials")
			}
		} else {
			response(w, false, "The user doesn't exist")
		}
	} else {
		response(w, false, "Not valid username, use alphanumeric characters only.")
	}
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
		uStr := tokens.Owner(token)
		u := users[uStr]
		uStr += "/"

		switch req.Method {
		case http.MethodGet:
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				fmt.Println(err)
			}
			//The content of the body is the back up name so response the content of the backup
			if len(body) > 0 {
				//If the file is from other user, it's the name, if it's mine from=="me"
				from := req.Header.Get("from")
				//Read the content of the file
				var path string
				if from == "me" {
					path = backUpPath + uStr + string(body)
				} else {
					path = backUpPath + from + string(body)
				}
				content, err := ioutil.ReadFile(path)
				if err != nil {
					response(w, false, "Back up not found")
					fmt.Println(err)
				} else {
					w.Header().Add("key", u.GetKey(path))
					w.Write(content)
				}
			} else { //If the body is empty: list the content of the backups and response
				response(w, true, u.MyFiles())
			}

		case http.MethodPost:
			key := req.Header.Get("key")
			if key == "" {
				response(w, false, "Missing encryption key")
			} else {
				checkMkdir(backUpPath)
				body, err := ioutil.ReadAll(req.Body)
				if err != nil {
					response(w, false, "The file is empty")
				} else {
					checkMkdir(backUpPath + uStr)
					//Write the content on the file
					path := backUpPath + uStr + time.Now().String()
					err = ioutil.WriteFile(path, body, 0644)
					if err != nil {
						fmt.Println(err)
					}
					//Save in the database
					u.Files = append(u.Files, file{
						From:     "Me",
						Name:     path,
						Key:      key,
						IsShared: false,
					})
					err = saveDatabase()
					if err != nil {
						fmt.Println(err)
					}
					response(w, true, "File saved")
				}
			}
		}
	}
}

func shareHandler(w http.ResponseWriter, req *http.Request) {
	token := req.Header.Get("token")

	if _, exists := tokens.Exists(token); exists {
		uStr := tokens.Owner(token)
		u := users[uStr]

		switch req.Method {
		case http.MethodGet:
			sharedFiles := u.SharedFiles()
			response(w, true, sharedFiles)

		case http.MethodDelete:
			fileName := req.Header.Get("filename")
			newKey := req.Header.Get("newkey")

			err := u.StopSharing(fileName, newKey)
			if err != nil {
				response(w, false, err.Error())
			} else {
				for _, exfriend := range users {
					exfriend.DeleteSharedFileWithMe(fileName, uStr)
				}
				response(w, true, fileName+" is't shared now")
			}

		case http.MethodPost:
			fileName := req.Header.Get("filename")
			friendStr := req.Header.Get("friend")
			key := req.Header.Get("key")

			friend := users[friendStr]
			err := friend.AddSharedFileWithMe(fileName, key, uStr)
			if err != nil {
				response(w, false, err.Error())
			} else {
				response(w, true, "File shared successfully")
			}
		}
	}
}

func keysHandler(w http.ResponseWriter, req *http.Request) {
	token := req.Header.Get("token")
	if _, exists := tokens.Exists(token); exists {
		//If it wants the own keys from=="me", if it wants public key from a friend from is the friend's name
		from := req.Header.Get("from")
		if from == "me" {
			uStr := tokens.Owner(token)
			u := users[uStr]
			w.Header().Add("pubkey", u.PubKey)
			w.Header().Add("privkey", u.PrivKey)
			response(w, true, "Public and private keys sent successfully")
		} else {
			u, exists := users[from]
			if exists {
				w.Header().Add("pubkey", u.PubKey)
				response(w, true, "Public key sent successfully")
			} else {
				response(w, false, fmt.Sprintf("Friend %s not found", from))
			}
		}

	}
}

func keyfileHandler(w http.ResponseWriter, req *http.Request) {
	token := req.Header.Get("token")
	if _, exists := tokens.Exists(token); exists {
		filename := req.Header.Get("filename")
		if filename == "" {
			response(w, false, "Missing filename.")
		} else {
			uStr := tokens.Owner(token)
			filename = fmt.Sprintf("%s%s/%s", backUpPath, uStr, filename)
			u := users[uStr]
			key := u.GetKey(filename)
			if key == "" {
				response(w, false, "File not found")
			} else {
				response(w, true, key)
			}
		}
	}
}
