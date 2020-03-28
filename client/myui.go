package main

import (
	"bytes"
	"html/template"
	"io/ioutil"
	"net/url"

	"github.com/zserge/lorca"
)

//MyUI is an struct to be able to charge views from javascript
type MyUI struct {
	ui lorca.UI
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
	date string
}

func (myui *MyUI) chargeViewTemplate(filePath string, dates []Date) {
	tmpl, err := template.ParseFiles(filePath)
	if err != nil {
		panic(err)
	}

	buff := bytes.Buffer{}

	err = tmpl.Execute(&buff, dates)
	if err != nil {
		panic(err)
	}
	myui.ui.Load("data:text/html," + url.PathEscape(string(buff.Bytes())))
}
