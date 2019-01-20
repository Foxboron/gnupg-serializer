package serializer

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"strconv"
)

func GetSegment(r *bufio.Reader) []byte {
	for {
		c, err := r.Peek(1)
		if err == io.EOF {
			return nil
		}
		if byte(c[0]) == ')' || byte(c[0]) == '(' {
			r.ReadByte()
		} else {
			break
		}
	}
	cc, err := r.ReadBytes(':')
	if err != nil {
		return nil
	}
	cc = bytes.TrimSuffix(cc, []byte{':'})
	length, err := strconv.Atoi(string(cc))
	if err != nil {
		log.Fatal(err)
	}
	cc = make([]byte, length)
	r.Read(cc)
	return cc
}

func ParseRSAKey(r *bufio.Reader, key *RSAKey, pk *GPGKey) *GPGKey {
	pk.Key = key // Just make sure this is put together
	for {
		_, err := r.Peek(1)
		if err == io.EOF {
			break
		}
		switch string(GetSegment(r)) {
		case "n":
			key.N = GetSegment(r)
		case "e":
			key.E = GetSegment(r)
		case "d":
			key.D = GetSegment(r)
		case "p":
			key.P = GetSegment(r)
		case "q":
			key.Q = GetSegment(r)
		case "u":
			key.U = GetSegment(r)
		case "protected":
			pk.Encrypted = true
			key.ProtectionMode = ProtectionMode(GetSegment(r))
			key.Hash = string(GetSegment(r))
			key.Salt = GetSegment(r)
			if len(key.Salt) != 8 {
				log.Fatal("Invalid salt length")
			}
			key.Iterations, err = strconv.Atoi(string(GetSegment(r)))
			if err != nil {
				log.Fatal(err)
			}
			key.IV = GetSegment(r)
			if len(key.IV) != 16 {
				log.Fatal("Invalid IV length")
			}
			key.EncryptedStream = GetSegment(r)
		case "protected-at":
			key.ProtectedAt = GetSegment(r)
		case "comment":
			pk.Comment = string(GetSegment(r))
		case "uri":
			pk.Uri = string(GetSegment(r))
		case "hash":
			GetSegment(r)
			key.Checksum = GetSegment(r)
		}
	}
	return pk
}

func Parse(r *bufio.Reader) *GPGKey {
	switch Mode(GetSegment(r)) {
	case ProtectedPrivateKeyMode:
	default:
		log.Fatal("Unsupported")
	}
	var key *GPGKey
	switch Encryption(GetSegment(r)) {
	case RSA:
		key = ParseRSAKey(r, &RSAKey{}, &GPGKey{})
	case ELG:
	case DSA:
	case ECC:
	default:
		log.Fatal("Unsupported")
	}
	return key
}
