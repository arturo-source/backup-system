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

type file struct {
	From     string `json:"from"`
	Name     string `json:"name"`
	Key      string `json:"key"`
	IsShared bool   `json:"is_shared"`
}

type user struct {
	Username          string `json:"name"`
	PasswordHashed    []byte `json:"pass"`
	Salt              []byte `json:"salt"`
	PubKey            string `json:"pubkey"`
	PrivKey           string `json:"privkey"`
	Files             []file `json:"files"`
	SharedFilesWithMe []file `json:"shared_files_with_me"`
}

//GetKey receives filename and returns the key or empty string if the file doesn't exist
func (u *user) GetKey(filename string) string {
	for _, f := range u.Files {
		if filename == f.Name {
			return f.Key
		}
	}
	for _, f := range u.SharedFilesWithMe {
		if filename == f.Name {
			return f.Key
		}
	}
	return ""
}

//MyFiles returns a string with all user files separated by coma
func (u *user) MyFiles() string {
	pathLen := len(backUpPath) + len(u.Username) + 1
	files := ""
	for _, f := range u.Files {
		files += f.Name[pathLen:] + ","
	}
	for _, f := range u.SharedFilesWithMe {
		pathLen = len(backUpPath) + len(f.From) + 1
		files += f.Name[pathLen:] + ","
	}
	//Delete last coma
	if len(files) > 0 {
		files = files[:len(files)-1]
	}
	return files
}

//SharedFiles returns a string with shared files separated by coma
func (u *user) SharedFiles() string {
	pathLen := len(backUpPath) + len(u.Username) + 1
	sharedFilesString := ""
	for _, f := range u.Files {
		if f.IsShared {
			sharedFilesString += f.Name[pathLen:] + ","
		}
	}
	//Delete last coma
	if len(sharedFilesString) > 0 {
		sharedFilesString = sharedFilesString[:len(sharedFilesString)-1]
	}
	return sharedFilesString
}

//StopSharing sets a new encryption key for the file and sets IsShared to false
func (u *user) StopSharing(fileName, newKey string) error {
	if fileName == "" || newKey == "" {
		return fmt.Errorf("Not valid credentials")
	}

	for i, f := range u.Files {
		if f.Name == fileName {
			u.Files[i].IsShared = false
			u.Files[i].Key = newKey
			return nil
		}
	}

	return fmt.Errorf("File %s not found", fileName)
}

//AddSharedFileWithMe adds a friend file to SharedFilesWithMe
func (u *user) AddSharedFileWithMe(fileName, key, from string) error {
	for _, f := range u.SharedFilesWithMe {
		if f.Name == fileName {
			return fmt.Errorf("Error: file already shared with %s", u.Username)
		}
	}
	u.SharedFilesWithMe = append(u.SharedFilesWithMe,
		file{
			From:     from,
			Name:     fileName,
			Key:      key,
			IsShared: false,
		})
	return nil
}

//DeleteSharedFileWithMe deletes an exfriend file to SharedFilesWithMe
func (u *user) DeleteSharedFileWithMe(fileName, from string) {
	for i, f := range u.SharedFilesWithMe {
		if f.Name == fileName && f.From == from {
			//Delete f from the files array
			u.SharedFilesWithMe[i] = u.SharedFilesWithMe[len(u.SharedFilesWithMe)-1]
			u.SharedFilesWithMe = u.SharedFilesWithMe[:len(u.SharedFilesWithMe)-1]
		}
	}
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
