package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
)

type user struct {
	username       string
	passwordHashed []byte
}

func (u *user) Hash(password string) {
	hash := sha256.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		panic(err)
	}
	u.passwordHashed = hash.Sum(nil)
}

func (u *user) CompareHash(passwordToCompare string) bool {
	hash := sha256.New()
	_, err := hash.Write([]byte(passwordToCompare))
	if err != nil {
		panic(err)
	}
	passwordHashed := hash.Sum(nil)

	return bytes.Compare(u.passwordHashed, passwordHashed) == 0
}

// Group of users registered on the server
var users map[string]user

// Response type to comunicate with the client
type resp struct {
	Ok  bool
	Msg string
}

func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}
	rJSON, err := json.Marshal(&r)
	if err != nil {
		panic(err)
	}
	w.Write(rJSON)
}

func main() {
	http.HandleFunc("/", handler)

	err := http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", nil)
	if err != nil {
		panic(err)
	}
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	w.Header().Set("Content-Type", "text/plain")

	switch req.Form.Get("comand") { // The requested action
	case "register":
		u := user{}
		u.username = req.Form.Get("username")
		password := req.Form.Get("passwd")

		u.Hash(password)

		_, ok := users[u.username] // Is the user in the db?
		if ok {
			response(w, false, "Usuario ya registrado")
		} else {
			users[u.username] = u
			response(w, true, "Usuario registrado")
		}

	case "login":
		u, ok := users[req.Form.Get("username")] // Is the user in the db?
		if ok {
			password := req.Form.Get("passwd")
			if u.CompareHash(password) { // The password hashed match
				response(w, true, "Credenciales válidas")
			} else {
				response(w, false, "Credenciales inválidas")
			}
		} else {
			response(w, false, "Usuario inexistente")
			return
		}
	default:
		response(w, false, "Comando inválido")
	}
}
