package serializer

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

type RSAKey struct {
	N               []byte
	E               []byte
	D               []byte
	P               []byte
	Q               []byte
	U               []byte
	Checksum        []byte
	ProtectionMode  ProtectionMode
	Hash            string
	Salt            []byte
	IV              []byte
	Iterations      int
	ProtectedAt     []byte
	EncryptedStream []byte
}

func (k *GPGKey) DecryptRSAKey(pw []byte) {
	pk := k.Key.(*RSAKey)
	h := sha1.New()
	key := make([]byte, packet.CipherAES128.KeySize())
	s2k.Iterated(key, h, pw, pk.Salt, pk.Iterations)
	block, _ := aes.NewCipher(key)
	cbc := cipher.NewCBCDecrypter(block, pk.IV)
	data := make([]byte, len(pk.EncryptedStream))
	cbc.CryptBlocks(data, pk.EncryptedStream)
	ParseRSAKey(bufio.NewReader(bytes.NewReader(data)), pk, k) //Fill inn missing values
	k.Encrypted = false
	if !k.RSAVerify() {
		log.Fatal("checksum mismatch")
	}
}

func (k *GPGKey) FormatRSA() []byte {
	pk := k.Key.(*RSAKey)
	out := "(3:rsa"
	out += fmt.Sprintf("(1:n%d:%s)", len(pk.N), pk.N)
	out += fmt.Sprintf("(1:e%d:%s)", len(pk.E), pk.E)
	out += fmt.Sprintf("(1:d%d:%s)", len(pk.D), pk.D)
	out += fmt.Sprintf("(1:p%d:%s)", len(pk.P), pk.P)
	out += fmt.Sprintf("(1:q%d:%s)", len(pk.Q), pk.Q)
	out += fmt.Sprintf("(1:u%d:%s)", len(pk.U), pk.U)
	out += fmt.Sprintf("(12:protected-at%d:%s)", len(pk.ProtectedAt), pk.ProtectedAt)
	out += ")"
	return []byte(out)
}

func (k *GPGKey) RSAVerify() bool {
	if k.Encrypted {
		return false
	}
	pk := k.Key.(*RSAKey)
	h := sha1.New()
	h.Write(k.FormatRSA())
	return hex.EncodeToString(h.Sum(nil)) == hex.EncodeToString(pk.Checksum)
}
