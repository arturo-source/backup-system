package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type user struct {
	Username       string `json:"name"`
	PasswordHashed []byte `json:"pass"`
}

func (u *user) Hash(password []byte) {
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

// Group of users registered on the server
var users map[string]user

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
	data, err := ioutil.ReadFile("bbdd")
	if err != nil {
		panic(err)
	}
	users = make(map[string]user)

	// If the db is empty, then you don't have to Unmarshal
	// Because it causes error
	if len(data) > 0 {
		err = json.Unmarshal(data, &users)
		if err != nil {
			panic(err)
		}
	}

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/backup", backupHandler)

	err = http.ListenAndServeTLS(":9043", "certificates/server.crt", "certificates/server.key", nil)
	if err != nil {
		panic(err)
	}
}

// Response "Usuario registrado" if register have been possible
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
		response(w, false, "Usuario ya registrado")
	} else {
		users[u.Username] = u
		// Parsing the map to array of bytes
		uJSON, err := json.Marshal(users)
		if err != nil {
			panic(err)
		}
		// This array of bytes is written in the db
		err = ioutil.WriteFile("bbdd", uJSON, 0644)
		if err != nil {
			panic(err)
		}
		response(w, true, "Usuario registrado")
	}
}

// Response "Credenciales válidas" if data is Ok
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
			response(w, true, "Credenciales válidas")
		} else {
			response(w, false, "Credenciales inválidas")
		}
	} else {
		response(w, false, "Usuario inexistente")
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
			//TODO: Check if the user exist in the db
			//and recover from its directory
			//Read the content of the file
			content, err := ioutil.ReadFile("backups/" + string(body))
			if err != nil {
				fmt.Println(err)
			} else {
				w.Write(content)
			}
		} else {
			content := ""
			file, err := os.Open("backups")
			if err != nil {
				fmt.Printf("failed opening directory: %s\n", err)
			}
			defer file.Close()

			list, _ := file.Readdirnames(0) // 0 to read all files and folders
			for _, name := range list {
				content += name + ","
			}
			response(w, true, content)
		}

	case http.MethodPost:
		//Creates the directory if it doesn't exist
		if _, err := os.Stat("backups"); os.IsNotExist(err) {
			os.Mkdir("backups", 0755)
		}
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			response(w, false, "Contenido del archivo vacío")
		} else {
			//TODO: Check if the user exist in the db
			//and add the backup to its directory
			//Write the content on the file
			err = ioutil.WriteFile("backups/"+time.Now().String(), body, 0755)
			if err != nil {
				fmt.Println(err)
			}
			response(w, true, "Archivo guardado")
		}
	}
}
