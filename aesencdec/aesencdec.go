package aesencdec

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	log "github.com/sirupsen/logrus"
)

//Encrypt - to encrypt the given text using key
func Encrypt(keyStr, textStr string) (output string, err error) {
	keyStr = getCorrectKey(keyStr)
	key := []byte(keyStr)
	text := []byte(textStr)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Errorf("Error in creating the new Cipher : %v", err)
		return "", err
	}

	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func getCorrectKey(input string) (output string) {
	if len(input) > 32 {
		output = input[:32]
	} else if len(input) < 32 {
		output = input
		for i := 0; i < (32 - len(input)); i++ {
			output += "a"
		}
	} else {
		output = input
	}
	return
}

//Decrypt - to Decrypt the cryptoText with the key
func Decrypt(key, cryptoText string) (output string, err error) {
	key = getCorrectKey(key)

	text, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		log.Errorf("Error in Decoding string : %v", err)
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	if len(text) < aes.BlockSize {
		return "", errors.New("CipherText Too short")
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		log.Errorf("Error in decoding the string : %v", err)
		return "", err
	}
	return string(data), nil
}
