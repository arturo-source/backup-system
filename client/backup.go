package main

import (
	"fmt"
	"time"
)

type backUp struct {
	nextBackUpTime time.Duration
	// stopchan       chan struct{}
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
		return fmt.Errorf("Error: time isn't set")
	}
	return nil
}

func (b *backUp) start(u user, path string) {
	// b.stopchan = make(chan struct{})
	go func() {
		for {
			// select {
			// case <-b.stopchan: //if
			// 	b.nextBackUpTime = 0 * time.Second
			// 	fmt.Println("Back up timer finished")
			// 	close(b.stopchan)
			// 	return
			// default:
			err := b.waitNextBackUp()
			if err != nil {
				fmt.Println(err)
				return
			}
			_, err = u.SendBackUpToServer(path, true)
			if err != nil {
				fmt.Println(err)
			}
			// }
		}
	}()
}
