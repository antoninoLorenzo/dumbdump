package internals

import (
	"fmt"
	"net/http"
	"net/url"
)

type Browser interface {
	New() (Browser, error)

	Name()

	// Returns [][]Credentials -> Credentials for each Profile
	DumpCredentials() ([][]Credentials, error)

	// Returns [][]Cookie -> Cookies for each Profile
	DumpCookies() ([][]http.Cookie, error)

	// Browser specific logic to decrypt the password.
	// Note: it is used internally by DumpCredentials()
	// The `psw` is passed as a reference to the ciphertext.
	DecryptPassword(psw *[]byte)
}

type Credentials struct {
	LoginUrl *url.URL
	Username string
	Password []byte
	// Add date to order
}

const (
	BOLD_START = "\033[1m"
	BOLD_END   = "\033[0m"
)

func (c Credentials) PrintCredentials() {
	fmt.Printf("%s%s %s \n%s:%s\n", BOLD_START, c.LoginUrl, BOLD_END, c.Username, string(c.Password))
}
