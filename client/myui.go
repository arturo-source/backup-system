package main

import (
	"bytes"
	"html/template"
	"io/ioutil"
	"net/url"
	"strings"

	"github.com/zserge/lorca"
)

//MyUI is an struct to be able to charge views from javascript
type MyUI struct {
	ui lorca.UI
	u  user
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
