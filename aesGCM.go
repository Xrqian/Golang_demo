package xaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
)

func EncryptGCM(screat_key string, message string) (encrypt_message string, err error) {
	key, _ := hex.DecodeString(screat_key)
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error", err)
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		err = errors.New("key错误")
	}
	content := []byte(message)
	ciphertext := aesgcm.Seal(nil, nonce, content, nil)
	encrypt_message = base64.StdEncoding.EncodeToString(nonce) + base64.StdEncoding.EncodeToString(ciphertext)
	return encrypt_message, err
}

func DecryptGCM(screat_key string, encryptedString string) (raw_data string, err error) {
	key, _ := hex.DecodeString(screat_key)
	encryptedData, _ := base64.StdEncoding.DecodeString(encryptedString)
	nonce := encryptedData[0:12]
	ciphertext := encryptedData[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		err = errors.New("key错误")
	}
	aesgcm, err := cipher.NewGCM(block)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err = errors.New("解密失败")
	}
	raw_data = hex.EncodeToString(plaintext[:])
	return raw_data, err
}
