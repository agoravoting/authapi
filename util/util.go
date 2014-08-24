package util

import (
	"os"
	"io"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Contents reads a file into a string
func Contents(filepath string) (string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close()  // f.Close will run when we're finished.

	var result []byte
	buf := make([]byte, 100)
	for {
		n, err := f.Read(buf[0:])
		result = Append(result, buf[0:n])
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err  // f will be closed if we return here.
		}
	}
	return string(result), nil // f will be closed if we return here.
}

// Append bytes to a slice
func Append(slice, data[]byte) []byte {
	l := len(slice)
	if l + len(data) > cap(slice) {  // reallocate
		// Allocate double what's needed, for future growth.
		newSlice := make([]byte, (l+len(data))*2)
		// The copy function is predeclared and works for any slice type.
		copy(newSlice, slice)
		slice = newSlice
	}
	slice = slice[0:l+len(data)]
	for i, c := range data {
		slice[l+i] = c
	}
	return slice
}

// Generates an HMAC using SHA256
func GenerateMAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	ret := make([]byte, 64)
	hex.Encode(ret, mac.Sum(nil))
	return ret
}

// CheckMAC returns true if messageMAC is a valid HMAC tag for message. Uses SHA256.
func CheckMAC(message, messageMAC, key []byte) bool {
	expectedMAC := GenerateMAC(message, key)

	// careful! use hmac.Equal to be safe against timing side channel attacks
	return hmac.Equal(messageMAC, expectedMAC)
}
