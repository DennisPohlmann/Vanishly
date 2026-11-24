package vanishly

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type vector struct {
	Name, Plaintext, Passphrase, Key string
	Payload
	Verifier *string `json:"verifier"`
}

func vectors(t *testing.T) []vector {
	b, err := os.ReadFile("../testvectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Vectors []vector }
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Vectors
}

func must(t *testing.T, s string) []byte {
	b, err := FromB64url(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectorsFromJavaScript(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			key, p, err := encrypt(v.Plaintext, v.Passphrase, v.Iterations, must(t, v.Key), must(t, v.Salt), must(t, v.IV))
			if err != nil || key != v.Key || p.Ciphertext != v.Ciphertext {
				t.Fatalf("encrypt differs: %v %s", err, p.Ciphertext)
			}
			want := ""
			if v.Verifier != nil {
				want = *v.Verifier
			}
			if p.Verifier != want {
				t.Fatalf("verifier %q, want %q", p.Verifier, want)
			}
			var pk []byte
			if v.Passphrase != "" {
				if pk, err = UnlockKey(v.Passphrase, v.Salt, v.Iterations); err != nil {
					t.Fatal(err)
				}
				if got, _ := VerifierFor(pk, v.Salt); got != want {
					t.Fatalf("VerifierFor %q", got)
				}
			}
			got, err := DecryptSecret(v.Payload, v.Key, pk)
			if err != nil || got != v.Plaintext {
				t.Fatalf("decrypt: %v %q", err, got)
			}
		})
	}
}

func TestWrongKeyAndTampering(t *testing.T) {
	for _, v := range vectors(t) {
		if v.Passphrase == "" {
			continue
		}
		pk, _ := UnlockKey(v.Passphrase, v.Salt, v.Iterations)
		if _, err := DecryptSecret(v.Payload, v.Key, nil); !errors.Is(err, ErrDecrypt) {
			t.Fatal("decrypted without passphrase")
		}
		ct := must(t, v.Ciphertext)
		ct[0] ^= 1
		p := v.Payload
		p.Ciphertext = ToB64url(ct)
		if _, err := DecryptSecret(p, v.Key, pk); !errors.Is(err, ErrDecrypt) {
			t.Fatal("decrypted tampered data")
		}
		return
	}
}

func TestRoundTripAndLink(t *testing.T) {
	key, p, err := EncryptSecret("hällo 🔐", "pw")
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := UnlockKey("pw", p.Salt, p.Iterations)
	if s, err := DecryptSecret(p, key, pk); err != nil || s != "hällo 🔐" {
		t.Fatal(s, err)
	}
	id, k := "AAAAAAAAAAAAAAAAAAAAAA", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if b, i, kk, err := ParseLink("https://x.example/ots/s/" + id + "#" + k); err != nil || b != "https://x.example/ots" || i != id || kk != k {
		t.Fatal(b, err)
	}
	if _, _, _, err := ParseLink("https://x.example/s/short#k"); err == nil {
		t.Fatal("bad link accepted")
	}
	if _, err := FromB64url("a+b/"); err == nil {
		t.Fatal("bad base64url accepted")
	}
}
