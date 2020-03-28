package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
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
	http.HandleFunc("/backup", loginHandler)

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
