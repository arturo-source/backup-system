package main

import (
	"fmt"
	"time"
)

type backUp struct {
	nextBackUpTime time.Duration
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
		return fmt.Errorf("Error: time not set")
	}
	return nil
}
