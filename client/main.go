package main

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"

	"github.com/zserge/lorca"
)

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

func main() {
	u := user{}
	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}

	ui, err := lorca.New("", "", 480, 320, args...)
	if err != nil {
		panic(err)
	}
	defer ui.Close()
	myui := MyUI{ui}

	myui.chargeView("./www/index.html")
	ui.Bind("SignIn", u.SignIn)
	ui.Bind("SignUp", u.SignUp)
	ui.Bind("EncryptFile", u.EncryptFile)
	ui.Bind("DecryptFile", u.DecryptFile)
	ui.Bind("SignUp", u.SignUp)
	ui.Bind("chargeView", myui.chargeView)
	ui.Bind("chargeViewTemplate", myui.chargeViewTemplate)

	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

	fmt.Println("exiting...")
}
