package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/url"
	"os"
	"strings"

	"github.com/zserge/lorca"
)

//MyUI is an struct to be able to charge views from javascript
type MyUI struct {
	ui lorca.UI
	u  user
}

func (myui *MyUI) addBackUp(path, time string) error {
	b := backUp{}
	err := b.fixTime(time)
	if err != nil {
		return err
	}
	b.start(myui.u, path)

	return nil
}

func (myui *MyUI) chargeView(filePath string) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		panic(err)
	}

	err = myui.ui.Load("data:text/html," + url.PathEscape(string(data)))
	if err != nil {
		panic(err)
	}
}

//Date is needed to show the date of the backups
type Date struct {
	Date string
}

func (myui *MyUI) chargeViewDownload(filePath string) {
	tmpl, err := template.ParseFiles(filePath)
	if err != nil {
		panic(err)
	}

	resp, err := myui.u.ListFiles()
	if err != nil {
		panic(err)
	}
	dates := []Date{}
	if resp.Ok && len(resp.Msg) > 0 {
		datesSplit := strings.Split(resp.Msg, ",")
		for _, d := range datesSplit {
			dates = append(dates, Date{d})
		}
	}

	buff := bytes.Buffer{}

	err = tmpl.Execute(&buff, dates)
	if err != nil {
		panic(err)
	}
	myui.ui.Load("data:text/html," + url.PathEscape(string(buff.Bytes())))
}

func (myui *MyUI) chargeDirectoryFirst(filePath string) {

	tmpl, err := template.ParseFiles(filePath)
	if err != nil {
		panic(err)
	}

	directories, err := chargeDirectory("/")
	if err != nil {
		panic(err)
	}

	buff := bytes.Buffer{}

	err = tmpl.Execute(&buff, directories)
	if err != nil {
		panic(err)
	}
	myui.ui.Load("data:text/html," + url.PathEscape(string(buff.Bytes())))
}

//Directory is needed to show the date of the backups
type Directory struct {
	Directory string
}

func chargeDirectory(filepath string) ([]Directory, error) {

	fmt.Println("esto es ->" + filepath)

	directories := make([]Directory, 0)

	fi, err := os.Stat(filepath)
	switch {
	case err != nil:
		// handle the error and return
	case fi.IsDir():
		// it's a directory

		files, err := ioutil.ReadDir(filepath)

		if err != nil {
			return directories, err
		}
		for _, file := range files {
			//directories = append(directories, Directory{filepath + file.Name()})
			if filepath == string(os.PathSeparator) {
				directories = append(directories, Directory{filepath + file.Name()})
			} else {
				directories = append(directories, Directory{filepath + string(os.PathSeparator) + file.Name()})
			}
		}
	default:
		// it's not a directory
	}
	return directories, nil
}
