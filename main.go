package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/zserge/lorca"
)

type backUp struct {
	nextBackUpTime time.Duration
}

func (b *backUp) fixTime(nextBackUp string) error {
	var err error
	b.nextBackUpTime, err = time.ParseDuration(nextBackUp)
	if err != nil {
		return err
	}
	return nil
}
func (b *backUp) waitNextBackUp() {
	<-time.After(b.nextBackUpTime)
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

	// Load HTML.
	// You may also use `data:text/html,<base64>` approach to load initial HTML,
	// e.g: ui.Load("data:text/html," + url.PathEscape(html))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.FileServer(FS))
	ui.Load(fmt.Sprintf("http://%s", ln.Addr()))

	ui.Bind("logIn", u.SignIn)

	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}

	log.Println("exiting...")
}
