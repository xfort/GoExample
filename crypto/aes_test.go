package crypto

import (
	"testing"
	"io/ioutil"
	"path/filepath"
)

func TestAESCrypto_CBCEncrypter(t *testing.T) {
	aesHandler := &AESCrypto{}
	fileDir := "/home/tongying/work/goland/data"
	outfile := filepath.Join(fileDir, "encrypted.data")

	fileBytes, err := ioutil.ReadFile(filepath.Join(fileDir, "1VID_20180803_155649.mp4"))
	if err != nil {
		t.Fatal(err)
	}

	resBytes, err := aesHandler.CBCEncrypter("123", fileBytes)
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile(outfile, resBytes, 0666)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAESCrypto_CBCDecrypter(t *testing.T) {
	aesHandler := &AESCrypto{}
	fileDir := "/home/tongying/work/goland/data"
	outfile := filepath.Join(fileDir, "encrypted.data")

	filebytes, err := ioutil.ReadFile(outfile)
	if err != nil {
		t.Fatal(err)
	}
	decryptedData, err := aesHandler.CBCDecrypter("123", filebytes)
	if err != nil {
		t.Fatal(err)
	}
	err = ioutil.WriteFile(filepath.Join(fileDir, "test.mp4"), decryptedData, 0666)
	if err != nil {
		t.Fatal(err)
	}
}
