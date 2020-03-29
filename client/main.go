package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/zserge/lorca"
)

func main() {
	u := user{}
	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}

	ui, err := lorca.New("", "", 430, 510, args...)
	if err != nil {
		panic(err)
	}
	defer ui.Close()
	myui := MyUI{ui}

	// myui.chargeViewTemplate("www/download.html")

	myui.chargeView("./www/index.html")
	ui.Bind("SignIn", u.SignIn)
	ui.Bind("SignUp", u.SignUp)
	ui.Bind("EncryptFile", u.EncryptFile)
	ui.Bind("DecryptFile", u.DecryptFile)
	ui.Bind("SignUp", u.SignUp)
	ui.Bind("chargeView", myui.chargeView)
	ui.Bind("chargeViewTemplate", myui.chargeViewTemplate)
	ui.Bind("SendBackUpToServer", u.SendBackUpToServer)

	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

	fmt.Println("exiting...")
}
