package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"testing"
)

func TestAccountInfoEncoding(t *testing.T) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	a := accountInfo{
		Key: privateKeyWrapper(*sk),
		Kid: "kid",
	}

	buffer := bytes.NewBuffer(nil)
	err = json.NewEncoder(buffer).Encode(a)
	if err != nil {
		t.Fatal(err)
	}

	var a2 accountInfo
	err = json.NewDecoder(buffer).Decode(&a2)
	if err != nil {
		t.Fatal(err)
	}
	if a2.Kid != a.Kid {
		t.Fatal("kid not equal")
	}
	if !a2.Key.Equal(&sk.PublicKey) || a2.Key.D.Cmp(sk.D) != 0 {
		t.Fatal("key not equal")
	}
}

func TestNewCsr(t *testing.T) {
	domain := "example.com"
	certReq := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames: []string{domain},
	}
	s, _, err := generateKey(KeyECDSA)
	if err != nil {
		t.Fatal(err)
	}
	rawCsr, err := x509.CreateCertificateRequest(rand.Reader, &certReq, s)
	if err != nil {
		t.Fatal(err)
	}

	_, err = x509.ParseCertificateRequest(rawCsr)
	if err != nil {
		t.Fatal(err)
	}
}
