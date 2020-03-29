package main

import "fmt"

func main() {
	u := user{}
	// args := []string{}
	// if runtime.GOOS == "linux" {
	// 	args = append(args, "--class=Lorca")
	// }

	// ui, err := lorca.New("", "", 430, 510, args...)
	// if err != nil {
	// 	panic(err)
	// }
	// defer ui.Close()
	// myui := MyUI{ui, u}
	resp, err := u.SignIn("arturo", "holamundo")
	if err != nil {
		panic(err)
	} else {
		fmt.Println(resp)
	}
	resp, err = u.RecoverBackUp("2020-03-29 20:49:07.340299872 +0200 CEST m=+183.403360608")
	if err != nil {
		panic(err)
	} else {
		fmt.Println(resp)
	}

	// myui.chargeViewDownload("www/download.html")

	// myui.chargeView("./www/index.html")
	// ui.Bind("SignIn", myui.u.SignIn)
	// ui.Bind("SignUp", myui.u.SignUp)
	// ui.Bind("EncryptFile", myui.u.EncryptFile)
	// ui.Bind("DecryptFile", myui.u.DecryptFile)
	// ui.Bind("chargeView", myui.chargeView)
	// ui.Bind("chargeViewDownload", myui.chargeViewDownload)
	// ui.Bind("SendBackUpToServer", myui.u.SendBackUpToServer)
	// ui.Bind("RecoverBackUp", myui.u.RecoverBackUp)
	// // Wait until the interrupt signal arrives or browser window is closed
	// sigc := make(chan os.Signal)
	// signal.Notify(sigc, os.Interrupt)
	// select {
	// case <-sigc:
	// case <-ui.Done():
	// }

	// fmt.Println("exiting...")
}
