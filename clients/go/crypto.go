// Package vanishly is the Go client of Vanishly: end-to-end encrypted
// one-time secrets (crypto format v1, the same as public/js/vanishly-crypto.js)
// and the whole API (/api/v1). Standard library only.
package vanishly

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
)

// Format v1:
//
//	key        32 random bytes, only ever in the URL fragment (#...)
//	pk         without passphrase empty, else PBKDF2-SHA256(passphrase, salt, iterations, 32)
//	encKey     HKDF-SHA256(ikm = key || pk, salt, info "vanishly v1 enc")
//	verifier   HKDF-SHA256(ikm = pk, salt, info "vanishly v1 auth"); the server keeps SHA-256(verifier)
//	ciphertext AES-256-GCM(encKey, iv 12 bytes, aad "vanishly v1")
const (
	FormatVersion    = 1
	PBKDF2Iterations = 600000
)

var (
	aad = []byte("vanishly v1")
	// ErrDecrypt: wrong key or passphrase, or damaged data.
	ErrDecrypt = errors.New("cannot decrypt: wrong key or passphrase, or damaged data")
	b64        = base64.RawURLEncoding
	b64re      = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
)

// Payload is what POST /v1/secrets takes and the reveal API returns.
type Payload struct {
	V          int    `json:"v,omitempty"`
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Verifier   string `json:"verifier,omitempty"`
}

// ToB64url encodes without padding.
func ToB64url(b []byte) string { return b64.EncodeToString(b) }

// FromB64url decodes base64url without padding.
func FromB64url(s string) ([]byte, error) {
	if !b64re.MatchString(s) || len(s)%4 == 1 {
		return nil, errors.New("invalid base64url")
	}
	return b64.DecodeString(s)
}

func derive(ikm, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, salt, info, 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// UnlockKey stretches a passphrase once (pk); salt is the base64url value of the secret.
func UnlockKey(passphrase, salt string, iterations int) ([]byte, error) {
	s, err := FromB64url(salt)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(sha256.New, passphrase, s, iterations, 32)
}

// VerifierFor is the verifier the reveal API checks for a passphrase-protected secret.
func VerifierFor(pk []byte, salt string) (string, error) {
	s, err := FromB64url(salt)
	if err != nil {
		return "", err
	}
	v, err := derive(pk, s, "vanishly v1 auth")
	return ToB64url(v), err
}

// EncryptSecret encrypts a secret: the key goes into the URL fragment, the
// payload to POST /v1/secrets.
func EncryptSecret(plaintext, passphrase string) (key string, p Payload, err error) {
	k, salt, iv := make([]byte, 32), make([]byte, 16), make([]byte, 12)
	for _, b := range [][]byte{k, salt, iv} {
		if _, err = rand.Read(b); err != nil {
			return
		}
	}
	return encrypt(plaintext, passphrase, PBKDF2Iterations, k, salt, iv)
}

func encrypt(plaintext, passphrase string, iterations int, k, salt, iv []byte) (string, Payload, error) {
	var pk []byte
	var err error
	if passphrase != "" {
		if pk, err = pbkdf2.Key(sha256.New, passphrase, salt, iterations, 32); err != nil {
			return "", Payload{}, err
		}
	}
	encKey, err := derive(append(append([]byte{}, k...), pk...), salt, "vanishly v1 enc")
	if err != nil {
		return "", Payload{}, err
	}
	a, err := gcm(encKey)
	if err != nil {
		return "", Payload{}, err
	}
	p := Payload{
		V: FormatVersion, Ciphertext: ToB64url(a.Seal(nil, iv, []byte(plaintext), aad)),
		IV: ToB64url(iv), Salt: ToB64url(salt), Iterations: iterations,
	}
	if pk != nil {
		v, err := derive(pk, salt, "vanishly v1 auth")
		if err != nil {
			return "", Payload{}, err
		}
		p.Verifier = ToB64url(v)
	}
	return ToB64url(k), p, nil
}

// DecryptSecret decrypts what the reveal API returned; pk from UnlockKey, nil without passphrase.
func DecryptSecret(p Payload, key string, pk []byte) (string, error) {
	k, err := FromB64url(key)
	if err != nil || len(k) != 32 {
		return "", ErrDecrypt
	}
	salt, err1 := FromB64url(p.Salt)
	iv, err2 := FromB64url(p.IV)
	ct, err3 := FromB64url(p.Ciphertext)
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != 12 {
		return "", ErrDecrypt
	}
	encKey, err := derive(append(k, pk...), salt, "vanishly v1 enc")
	if err != nil {
		return "", ErrDecrypt
	}
	a, err := gcm(encKey)
	if err != nil {
		return "", ErrDecrypt
	}
	pt, err := a.Open(nil, iv, ct, aad)
	if err != nil {
		return "", ErrDecrypt
	}
	return string(pt), nil
}
