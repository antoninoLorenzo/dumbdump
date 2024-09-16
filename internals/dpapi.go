package internals

import (
	"fmt"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *dataBlob) bytes() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

// Decrypts the private key for the credentials using DPAPI
func DecryptKey(key []byte) ([]byte, error) {
	crypt32 := syscall.NewLazyDLL("Crypt32.dll")
	kernel32 := syscall.NewLazyDLL("Kernel32.dll")
	unprotectDataProc := crypt32.NewProc("CryptUnprotectData")
	localFreeProc := kernel32.NewProc("LocalFree")

	var outBlob dataBlob
	r, _, err := unprotectDataProc.Call(
		uintptr(unsafe.Pointer(newBlob(key))),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed with error %w", err)
	}

	defer localFreeProc.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.bytes(), nil
}
