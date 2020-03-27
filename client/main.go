package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/zserge/lorca"
)

var ui lorca.UI

type backUp struct {
	nextBackUpTime time.Duration
}

func (b *backUp) fixTime(nextBackUp string) error {
	var err error
	b.nextBackUpTime, err = time.ParseDuration(nextBackUp)
	if err != nil {
		b.nextBackUpTime = 0 * time.Second
		return err
	}
	return nil
}
func (b *backUp) waitNextBackUp() error {
	if b.nextBackUpTime != 0 {
		<-time.After(b.nextBackUpTime)
	} else {
		return fmt.Errorf("Error: time not set")
	}
	return nil
}

func compress(data []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

func decompress(data []byte) []byte {
	var b bytes.Buffer
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		panic(err)
	}
	defer r.Close()

	io.Copy(&b, r)
	return b.Bytes()
}

func chargeView(filePath string) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}

	ui.Load("data:text/html," + url.PathEscape(string(data)))
}

type Date struct {
	date string
}

func chargeViewTemplate(filePath string, dates []Date) {
	tmpl := template.Must(template.ParseFiles(filePath))

	buff := bytes.Buffer{}

	tmpl.Execute(&buff, dates)

	ui.Load("data:text/html," + url.PathEscape(string(buff.Bytes())))
}

func main() {
	u := user{}
	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}

	ui, err := lorca.New("", "", 480, 320, args...)
	if err != nil {
		log.Fatal(err)
	}
	defer ui.Close()

	chargeView("./www/index.html")
	ui.Bind("SignIn", u.SignIn)
	ui.Bind("SignUp", u.SignUp)
	ui.Bind("EncryptFile", u.EncryptFile)
	ui.Bind("DecryptFile", u.DecryptFile)
	ui.Bind("SignUp", u.SignUp)
	ui.Bind("chargeView", chargeView)

	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

	log.Println("exiting...")
}
