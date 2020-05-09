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
	myui := MyUI{ui, u}

	myui.chargeView("./www/index.html")
	ui.Bind("SignIn", myui.u.SignIn)
	ui.Bind("SignUp", myui.u.SignUp)
	ui.Bind("EncryptFile", myui.u.EncryptFile)
	ui.Bind("DecryptFile", myui.u.DecryptFile)
	ui.Bind("chargeView", myui.chargeView)
	ui.Bind("SendBackUpToServer", myui.u.SendBackUpToServer)
	ui.Bind("RecoverBackUp", myui.u.RecoverBackUp)
	ui.Bind("chargeDirectoryFirst", myui.chargeDirectoryFirst)
	ui.Bind("chargeDirectory", chargeDirectory)
	ui.Bind("ListFiles", myui.u.ListFiles)
	ui.Bind("ShareFileWith", myui.u.ShareFileWith)
	ui.Bind("GetSharedFiles", myui.u.GetSharedFiles)
	ui.Bind("StopSharingFile", myui.u.StopSharingFile)
	ui.Bind("addBackUp", myui.addBackUp)

	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

	fmt.Println("exiting...")
}
