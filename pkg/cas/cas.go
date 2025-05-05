package cas

import (
	"auto-cert/pkg/ref"
	"crypto/x509"
	"encoding/pem"
	"errors"

	aliCas "github.com/alibabacloud-go/cas-20200407/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
)

type Client struct {
	c *aliCas.Client
}

func CreateClient(cfg *openapi.Config) (*Client, error) {
	c, err := aliCas.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{c}, nil
}

type CertificateDetail struct {
	Id          int64
	Issuer      string
	Cert        *x509.Certificate
	SerialNo    string
	Fingerprint string
	Algorithm   string
	NotBefore   int64
}

func (c *Client) GetCertificateDetail(certId int64) (*CertificateDetail, error) {
	req := &aliCas.GetUserCertificateDetailRequest{
		CertId:     ref.GetPointer(certId),
		CertFilter: ref.GetPointer(true),
	}

	resp, err := c.c.GetUserCertificateDetail(req)
	if err != nil {
		return nil, err
	}

	body := resp.Body
	block, _ := pem.Decode([]byte(ref.DerefOrDefault(body.Cert)))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("Failed to decode PEM block containing certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	cd := &CertificateDetail{
		Id:          ref.DerefOrDefault(body.Id),
		Issuer:      *body.Issuer,
		Cert:        leaf,
		SerialNo:    ref.DerefOrDefault(body.SerialNo),
		Fingerprint: ref.DerefOrDefault(body.Fingerprint),
		Algorithm:   ref.DerefOrDefault(body.Algorithm),
		NotBefore:   ref.DerefOrDefault(body.NotBefore),
	}
	return cd, nil
}
