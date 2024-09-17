package internals

import (
	"errors"
)

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
