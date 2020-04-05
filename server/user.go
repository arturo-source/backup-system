package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

type user struct {
	Username       string `json:"name"`
	PasswordHashed []byte `json:"pass"`
	Salt           []byte `json:"salt"`
}

func (u *user) Hash(password, salt []byte) {
	hash := sha256.New()
	//Write the password in the buffer
	_, err := hash.Write(password)
	if err != nil {
		panic(err)
	}
	//Write the salt in the buffer
	_, err = hash.Write(salt)
	if err != nil {
		panic(err)
	}
	//Save the salt to be used in the future
	u.Salt = salt
	u.PasswordHashed = hash.Sum(nil)
}

func (u *user) CompareHash(passwordToCompare []byte) bool {
	hash := sha256.New()
	_, err := hash.Write(passwordToCompare)
	if err != nil {
		panic(err)
	}
	_, err = hash.Write(u.Salt)
	if err != nil {
		panic(err)
	}
	passwordHashed := hash.Sum(nil)

	return bytes.Compare(u.PasswordHashed, passwordHashed) == 0
}

//EncryptContent receives an array of bytes and returns the same but encrypted
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

//DecryptContent receives an array of bytes encrypted and returns the same but decrypted
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
