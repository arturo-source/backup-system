package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"
)

//Periodical is to manage the periodical back ups
type Periodical struct {
	ID            int
	Path          string
	TimeToUpdload time.Duration
	NextUpload    time.Time
	stopchan      chan struct{}
}

//readPeriodicity is used to read the user periodicity config
func (u *user) readPeriodicity() error {
	u.periodicals = make([]Periodical, 0)
	content, err := ioutil.ReadFile(u.username + ".p")
	if err != nil {
		return err
	}

	decryptContent, err := u.decrypt(content, nil)
	if err != nil {
		return err
	}

	err = json.Unmarshal(decryptContent, &u.periodicals)
	if err != nil {
		return err
	}
	for i := range u.periodicals {
		u.periodicals[i].stopchan = make(chan struct{})
	}

	return nil
}

//loopPeriodicity is used to throw 1 go routine per periodicity
func (u *user) loopPeriodicity() {
	for i, p := range u.periodicals {
		if isOutdated(p.NextUpload) {
			u.periodicals[i].NextUpload = time.Now().Add(p.TimeToUpdload)
		}
		go u.addPeriodicity(p)
	}
}

//isOutdated returns true if the date has expired
func isOutdated(date time.Time) bool {
	return time.Now().After(date)
}

//addPeriodicity is used to add one more go routine
func (u *user) addPeriodicity(p Periodical) {
	doBackUp := time.After(p.NextUpload.Sub(time.Now()))
	for {
		select {
		case <-p.stopchan:
			err := u.deletePeriodicity(p.ID)
			if err != nil {
				fmt.Println(err)
			}
			return
		case <-doBackUp:
			_, err := u.SendBackUpToServer(p.Path, true)
			if err != nil {
				fmt.Println(err)
			}
			doBackUp = time.After(p.TimeToUpdload)
			break
		}
	}
}

//AddPeriodicity is public because is used to comunicate from JavaScript, add a new periodicity and writes it in the config file
func (u *user) AddPeriodicity(path, nextBackUp string) (resp, error) {
	nextBackUpDuration, err := time.ParseDuration(nextBackUp)
	if err != nil {
		return resp{Ok: false, Msg: err.Error()}, err
	}
	nextUpload := time.Now().Add(nextBackUpDuration)
	id := 0
	if len(u.periodicals) > 0 {
		id = u.periodicals[len(u.periodicals)-1].ID + 1
	}
	p := Periodical{
		ID:            id,
		Path:          path,
		TimeToUpdload: nextBackUpDuration,
		NextUpload:    nextUpload,
		stopchan:      make(chan struct{}),
	}
	u.periodicals = append(u.periodicals, p)
	go u.addPeriodicity(p)

	content, err := json.Marshal(u.periodicals)
	if err != nil {
		return resp{Ok: false, Msg: err.Error()}, err
	}
	encryptedContent, err := u.encrypt(content, nil)
	if err != nil {
		return resp{Ok: false, Msg: err.Error()}, err
	}
	err = ioutil.WriteFile(u.username+".p", encryptedContent, 0644)
	if err != nil {
		return resp{Ok: false, Msg: err.Error()}, err
	}

	return resp{Ok: true, Msg: "Periodicity correctly added"}, nil
}

//deletePeriodicity deletes the periodicity with that id from the array and ovewrite the file
func (u *user) deletePeriodicity(id int) error {
	for i, p := range u.periodicals {
		if p.ID == id {
			// u.periodicals = append(u.periodicals[:i], u.periodicals[i+1:]...)
			u.periodicals[i] = u.periodicals[len(u.periodicals)-1]
			u.periodicals = u.periodicals[:len(u.periodicals)-1]
			content, err := json.Marshal(u.periodicals)
			if err != nil {
				return err
			}
			encryptedContent, err := u.encrypt(content, nil)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(u.username+".p", encryptedContent, 0644)
			if err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("ID %d not found", id)
}

//DeletePeriodicity is public because is used to comunicate from JavaScript, when the user wants to close the thread is doing the backups
func (u *user) DeletePeriodicity(idStr string) (resp, error) {
	ID, err := strconv.Atoi(idStr)
	if err != nil {
		return resp{Ok: false, Msg: err.Error()}, err
	}
	for i, p := range u.periodicals {
		if p.ID == ID {
			close(u.periodicals[i].stopchan)
			return resp{Ok: true, Msg: "Periodicity stopped"}, nil
		}
	}
	return resp{Ok: false, Msg: fmt.Sprintf("Periodicity %s not found", idStr)}, fmt.Errorf("Periodicity %s not found", idStr)
}

//PeriodicalParse is needed because the JavaScript used in front-end doesn't understand Periodical.TimeToUpdload
type PeriodicalParse struct {
	Path          string
	TimeToUpdload string
	ID            int
}

func (u *user) GetPeriodicity() []PeriodicalParse {
	periodicalsParse := make([]PeriodicalParse, 0)

	for _, period := range u.periodicals {
		periodicalsParse = append(periodicalsParse, PeriodicalParse{period.Path, period.TimeToUpdload.String(), period.ID})
	}
	return periodicalsParse
}
