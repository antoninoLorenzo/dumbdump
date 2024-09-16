package main

import (
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
		panic(err)
	}

	_, err = chrome.DumpCookies()
	if err != nil {
		panic(err)
	}
}
