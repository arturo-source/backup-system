package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

// Response type recieve from the server
type resp struct {
	Ok  bool
	Msg string
}

//user is used to log in the server, send and recover files, etc.
type user struct {
	username                  string
	passwordLogInServerHassed []byte
	cipherKey                 []byte
	httpclient                *http.Client
	token                     string
	pubKey                    *rsa.PublicKey
	privKey                   *rsa.PrivateKey
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
	u.pubKey = &rsa.PublicKey{}
	u.privKey = &rsa.PrivateKey{}
	return u.sign(username, password, "login")
}

//SignUp is used to register the user
func (u *user) SignUp(username, password string) (resp, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	privKey.Precompute()
	u.pubKey = &privKey.PublicKey
	u.privKey = privKey

	return u.sign(username, password, "register")
}

func (u *user) encrypt(content, key []byte) ([]byte, error) {
	if key == nil {
		key = u.cipherKey
	}
	//Creates the cipher
	c, err := aes.NewCipher(key)
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

//EncryptFile receives a filepath and write the same file but encrypted
func (u *user) EncryptFile(filePath string, key []byte) error {
	//Read the content of the file
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	encryptedContent, err := u.encrypt(content, key)
	if err != nil {
		return err
	}

	//Write the content on the file
	err = ioutil.WriteFile(filePath, encryptedContent, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (u *user) decrypt(content, key []byte) ([]byte, error) {
	if key == nil {
		key = u.cipherKey
	}
	//Creates the cipher
	c, err := aes.NewCipher(key)
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

//DecryptFile receives a filepath of a file encrypted and write the same file but decrypted
func (u *user) DecryptFile(filePath string, key []byte) error {
	//Read the content of the file
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	decryptedContent, err := u.decrypt(content, key)
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
	//Because not normal bytes can produce error when HTTP comunications
	data.Set("passwd", encode64(u.passwordLogInServerHassed))
	if command == "register" {
		//send keys as json to server
		pubKeyJSON, err := json.Marshal(u.pubKey)
		if err != nil {
			panic(err)
		}
		data.Set("pubkey", encode64(compressData(pubKeyJSON)))
		privKeyJSON, err := json.Marshal(u.privKey)
		if err != nil {
			panic(err)
		}
		data.Set("privkey", encode64(compressData(privKeyJSON)))
	}

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

	if command == "login" && response.Ok {
		//request keys to server
		req, err := http.NewRequest("GET", "https://localhost:9043/keys", nil)
		req.Header.Add("token", response.Msg)
		req.Header.Add("from", "me")

		res, err := u.httpclient.Do(req)
		if err != nil {
			return response, err
		}
		defer res.Body.Close()
		pubKeyJSON := res.Header.Get("pubkey")
		err = json.Unmarshal(uncompressData(decode64(pubKeyJSON)), u.pubKey)
		if err != nil {
			panic(err)
		}
		privKeyJSON := res.Header.Get("privkey")
		err = json.Unmarshal(uncompressData(decode64(privKeyJSON)), u.privKey)
		if err != nil {
			panic(err)
		}
	}

	return response, nil
}

//SendBackUpToServer sends a folder or file to the server
//but its previously compressed and encrypted
func (u *user) SendBackUpToServer(path string, isPeriodical bool) (resp, error) {
	//Generate name to the back up
	r, err := regexp.Compile("\\/(?:[vV][1-9]\\d?(?:-\\d)?\\/)?[^\\/]+$")
	if err != nil {
		panic(err)
	}
	backUpName := r.FindString(path)
	if isPeriodical {
		backUpName = fmt.Sprintf("%s;%s;", "periodical", backUpName)
	} else {
		backUpName = fmt.Sprintf("%s;%s;", "manual", backUpName)
	}
	//Generate encryption key
	key := RandStringBytes(16)
	response := resp{}
	//Creates a temporary file to compress, encrypt and send to the server
	err = compressFile(path, "compressed.zip")
	if err != nil {
		return response, err
	}
	err = u.EncryptFile("compressed.zip", key)
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
	req.Header.Add("backUpName", backUpName)
	key, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, u.pubKey, key, nil)
	if err != nil {
		return response, err
	}
	req.Header.Add("key", encode64(key))

	res, err := u.httpclient.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	//Unmarshal the response to a resp struct
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
	req.Header.Add("from", "me")

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
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, u.privKey, decode64(res.Header.Get("key")), nil)
	if err != nil {
		return response, err
	}
	err = u.DecryptFile("recover.zip", key)
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

	//Unmarshal the response to a resp struct
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	json.Unmarshal(body, &response)

	return response, nil
}

//ShareFileWith gets the key of the file and decrypt it with public key.
//After that sends the key encrypted with the friend's public key.
func (u *user) ShareFileWith(filename, username string) (resp, error) {
	response := resp{}
	req, err := http.NewRequest("GET", "https://localhost:9043/keyfile", nil)
	req.Header.Add("token", u.token)
	req.Header.Add("filename", filename)
	res, err := u.httpclient.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	//Unmarshal the response to a resp struct
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	json.Unmarshal(body, &response)

	if response.Ok {
		key := decode64(response.Msg)
		keyDecripted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, u.privKey, key, nil)
		if err != nil {
			return response, err
		}
		friendPubKey, err := u.getFriendPubKey(username)
		if err != nil {
			return response, err
		}
		keyEncriptedWithFriendPubKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, friendPubKey, keyDecripted, nil)
		if err != nil {
			return response, err
		}

		return u.shareFile(filename, username, encode64(keyEncriptedWithFriendPubKey))
	}
	return response, fmt.Errorf("Error: %s", response.Msg)
}
func (u *user) shareFile(filename, username, key string) (resp, error) {
	response := resp{}
	req, err := http.NewRequest("POST", "https://localhost:9043/share", nil)
	//To authorize the user
	req.Header.Add("token", u.token)
	req.Header.Add("friend", username)
	req.Header.Add("filename", filename)
	req.Header.Add("key", key)

	res, err := u.httpclient.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	//Unmarshal the response to a resp struct
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	json.Unmarshal(body, &response)

	return response, nil
}
func (u *user) getFriendPubKey(username string) (*rsa.PublicKey, error) {
	pubKey := &rsa.PublicKey{}
	response := resp{}
	req, err := http.NewRequest("GET", "https://localhost:9043/keys", nil)
	req.Header.Add("token", u.token)
	req.Header.Add("from", username)
	res, err := u.httpclient.Do(req)
	if err != nil {
		return pubKey, err
	}
	defer res.Body.Close()

	//Unmarshal the response to a resp struct
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return pubKey, err
	}
	json.Unmarshal(body, &response)

	if response.Ok {
		err = json.Unmarshal(uncompressData(decode64(res.Header.Get("pubkey"))), pubKey)
		if err != nil {
			return pubKey, err
		}
		return pubKey, nil
	}
	return pubKey, fmt.Errorf("Error: %s", response.Msg)
}

//StopSharingFile receives a filename and stops sharing it for all people
func (u *user) StopSharingFile(filename string) (resp, error) {
	response := resp{}
	key, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, u.pubKey, RandStringBytes(16), nil)
	if err != nil {
		return response, err
	}
	req, err := http.NewRequest("DELETE", "https://localhost:9043/share", nil)
	req.Header.Add("token", u.token)
	req.Header.Add("filename", filename)
	req.Header.Add("newkey", encode64(key))
	res, err := u.httpclient.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	//Unmarshal the response to a resp struct
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	json.Unmarshal(body, &response)

	return response, nil
}

//GetSharedFiles asks the server which files user has shared
func (u *user) GetSharedFiles() (resp, error) {
	response := resp{}
	req, err := http.NewRequest("GET", "https://localhost:9043/share", nil)
	req.Header.Add("token", u.token)
	res, err := u.httpclient.Do(req)
	if err != nil {
		return response, err
	}
	defer res.Body.Close()

	//Unmarshal the response to a resp struct
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return response, err
	}
	json.Unmarshal(body, &response)

	return response, nil
}
