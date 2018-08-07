package crypto

import (
	"encoding/hex"
	"crypto/aes"
	"crypto/cipher"
	"bytes"
	"fmt"
	"crypto/md5"
)

type AESCrypto struct {
}

/**CBC PKCS7Padding加密
 */
func (aescrypto *AESCrypto) CBCEncrypter(key string, plantData []byte) ([]byte, error) {

	hash := md5.New()
	_, err := hash.Write([]byte(key))
	if err != nil {
		return nil, err
	}
	key = fmt.Sprintf("%x", hash.Sum(nil))

	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	plantData = PKCS7Padding(plantData, block.BlockSize())

	cipherText := make([]byte, len(plantData))

	//iv := cipherText[:aes.BlockSize]
	//if _, err := io.ReadFull(rand.Reader, iv); err != nil {
	//	return nil, err
	//}
	mode := cipher.NewCBCEncrypter(block, keyBytes[:block.BlockSize()])
	mode.CryptBlocks(cipherText, plantData)
	//resCipherText:=base64.StdEncoding.EncodeToString(cipherText)
	return cipherText, nil
}

/**
CBC PKCS7Padding解密
 */
func (aesCrypto *AESCrypto) CBCDecrypter(key string, cipherData []byte) ([]byte, error) {
	hash := md5.New()
	_, err := hash.Write([]byte(key))
	if err != nil {
		return nil, err
	}
	key = fmt.Sprintf("%x", hash.Sum(nil))
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, keyBytes[:block.BlockSize()])
	plantData := make([]byte, len(cipherData))
	blockMode.CryptBlocks(plantData, cipherData)
	plantData = PKCS7UnPadding(plantData, block.BlockSize())
	return plantData, nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(plantText []byte, blockSize int) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}
