package internals

import (
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
	loginUrl *url.URL
	username string
	password []byte
	// Add date to order
}
