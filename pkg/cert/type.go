package cert

import (
	"bytes"
	"encoding/pem"
	"errors"
)

type KeyType uint

const (
	KeyRSA KeyType = iota + 1
	KeyECDSA
)

type Cert struct {
	keyType    KeyType
	publicKeys [][]byte
	privateKey []byte
}

func (c Cert) CertPemEncoded() ([]byte, error) {
	pemCert := bytes.Buffer{}
	if len := len(c.publicKeys); len == 0 {
		return nil, errors.New("public key is empty")
	}
	for _, b := range c.publicKeys {
		block := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: b,
		}
		if err := pem.Encode(&pemCert, &block); err != nil {
			return nil, err
		}
	}
	return pemCert.Bytes(), nil
}

func (c Cert) PrivateKeyPemEncoded() ([]byte, error) {
	if len(c.privateKey) == 0 {
		return nil, errors.New("private key is empty")
	}
	typeStr := ""
	switch c.keyType {
	case KeyRSA:
		typeStr = "RSA PRIVATE KEY"
	case KeyECDSA:
		typeStr = "EC PRIVATE KEY"
	default:
		return nil, errors.New("unsupported key type")
	}
	block := pem.Block{
		Type:  typeStr,
		Bytes: c.privateKey,
	}
	return pem.EncodeToMemory(&block), nil
}

func (c Cert) GeneratePemEncoded() (cert []byte, key []byte, err error) {
	cert, err = c.CertPemEncoded()
	if err != nil {
		return
	}
	key, err = c.PrivateKeyPemEncoded()
	if err != nil {
		return
	}
	return
}
