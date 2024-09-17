package main

import (
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/antoninoLorenzo/dumbdump/internals"
	_ "github.com/mattn/go-sqlite3"
)

type Runner func()

var Runners = map[string]Runner{
	"chrome": runChrome,
	"brave":  runBrave,
}

func Run(targets []string) {
	for _, t := range targets {
		if runner, ok := Runners[t]; ok {
			runner()
		} else {
			fmt.Printf("[!] Invalid target %s", t)
		}
	}
}

func runChrome() {
	chrome, err := internals.NewChrome()
	if err != nil {
		panic(err)
	}

	profileCredentials, err := chrome.DumpCredentials()
	if err != nil {
		fmt.Printf("[!] %s\n", err)
	}
	for _, credentialsList := range profileCredentials {
		for _, cred := range credentialsList {
			cred.PrintCredentials()
		}
	}

	/*
		_, err = chrome.DumpCookies()
		if err != nil {
			panic(err)
		}
	*/
}

func runBrave() {
	brave, err := internals.NewBrave()
	if err != nil {
		panic(err)
	}

	profileCredentials, err := brave.DumpCredentials()
	if err != nil {
		fmt.Printf("[!] %s\n", err)
	}
	for _, credentialsList := range profileCredentials {
		for _, cred := range credentialsList {
			cred.PrintCredentials()
		}
	}
}

func main() {
	targetPtr := flag.String(
		"target",
		"all",
		`Specify target browsers, otherwise "br1,br2,..."
		`,
	)
	flag.Parse()

	fmt.Printf("Test: %s\n", "\033[1mhi \033[0m")

	targets := make([]string, 0)
	if *targetPtr == "all" {
		targets = slices.Sorted(maps.Keys(Runners))
	} else {
		targets = strings.Split(*targetPtr, ",")
	}

	Run(targets)
}
