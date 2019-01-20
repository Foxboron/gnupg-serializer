package test

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/foxboron/gnupg-serializer/parser"
)

var (
	testFile = "./gnupg/private-keys-v1.d/BE68F7CF5CF7742F261FAD81C3F429723A280243.key"
)

func TestParser(t *testing.T) {
	data, err := os.Open(testFile)
	if err != nil {
		log.Fatal(err)
	}
	parser.Parse(bufio.NewReader(data))
	fmt.Println("lol")
}
