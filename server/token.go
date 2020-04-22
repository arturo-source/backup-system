package main

import "time"

//Token is the struct to control when a user can access it's data
type Token struct {
	value      string
	finishDate time.Time
	userName   string
}

//Tokens implements the functions to control the tokens in the server
type Tokens struct {
	tokens []Token
}

//Exists returns true and the position if finds the the token in the array
//but the token cannot be expired
func (t *Tokens) Exists(tokenValue string) (int, bool) {
	for i, token := range t.tokens {
		if token.value == tokenValue && !isOutdated(token) {
			return i, true
		}
	}
	return -1, false
}

//Add adds a token to the array to this user and return generated token
//the token is valid till 1 day
func (t *Tokens) Add(username string) string {
	tomorrow := time.Now().Add(24 * time.Hour)
	value := string(RandStringBytes(16))
	token := Token{
		value:      value,
		finishDate: tomorrow,
		userName:   username,
	}
	t.tokens = append(t.tokens, token)
	return value
}

//Delete returns true if finds the token, and deletes it.
func (t *Tokens) Delete(token Token) bool {
	i, exists := t.Exists(token.value)
	if exists {
		t.tokens[i] = t.tokens[len(t.tokens)-1]
		t.tokens = t.tokens[:len(t.tokens)-1]
		return true
	}

	return false
}

//DeleteExpireds looks all tokens and delete expireds
func (t *Tokens) DeleteExpireds() {
	for i, token := range t.tokens {
		if isOutdated(token) {
			t.tokens[i] = t.tokens[len(t.tokens)-1]
			t.tokens = t.tokens[:len(t.tokens)-1]
		}
	}
}

//Owner returns the username of a token or empty string if it doesn't exist
func (t *Tokens) Owner(tokenValue string) string {
	i, exists := t.Exists(tokenValue)
	if exists {
		return t.tokens[i].userName
	}
	return ""
}

//isOutdated returns true if the token has expired
func isOutdated(token Token) bool {
	return time.Now().After(token.finishDate)
}
