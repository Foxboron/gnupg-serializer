package serializer

type Mode string

const (
	ProtectedPrivateKeyMode Mode = "protected-private-key"
	PrivateKeyMode          Mode = "private-key"
	ShadowedKeyMode         Mode = "shadowed-private-key"
)

type Encryption string

const (
	RSA Encryption = "rsa"
	ELG Encryption = "elg"
	DSA Encryption = "dsa"
	ECC Encryption = "ecc"
)

type ProtectionMode string

const (
	S2k3SHA1AESCBC ProtectionMode = "openpgp-s2k3-sha1-aes-cbc"
	Native         ProtectionMode = "openpgp-native"
)

type GPGKey struct {
	Mode      Mode
	Encrypted bool
	Key       interface{} //  *{RSA}Key
	Uri       string
	Comment   string
}

func (k *GPGKey) Decrypt(pw []byte) {
	if !k.Encrypted {
		return
	}
	switch k.Key.(type) {
	case *RSAKey:
		k.DecryptRSAKey(pw)
	}
}

func (k *GPGKey) FormatKey() []byte {
	switch k.Key.(type) {
	case *RSAKey:
		k.FormatRSA()
	}
	return nil
}
