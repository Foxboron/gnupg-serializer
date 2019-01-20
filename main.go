package main

import (
	"bufio"
	"log"
	"os"

	"github.com/foxboron/gnupg-serializer/serializer"
)

var (
	testFile = "./test/gnupg/private-keys-v1.d/3E6D73DE73228226289805EB0F9CAB5E736E9EBF.key"
)

func main() {
	data, err := os.Open(testFile)
	if err != nil {
		log.Fatal(err)
	}
	key := serializer.Parse(bufio.NewReader(data))
	key.Decrypt([]byte{'c', 'l', 'a', 'v', 'e'})
	key.FormatRSA()
}
