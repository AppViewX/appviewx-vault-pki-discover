package aesencdec

import "testing"

func TestEncrypt(t *testing.T) {
	encryptedValue, err := Encrypt("key", "text")
	if err != nil {
		t.Fatalf("Error in encrypting")
	}

	decryptedValue, err := Decrypt("key", encryptedValue)
	if err != nil {
		t.Fatalf("Error in decrypting")
	}
	if decryptedValue != "text" {
		t.Fatalf("Encryption / Decryption Error")
	}
}
