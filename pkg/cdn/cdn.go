package cdn

import (
	"errors"
	"time"

	"auto-cert/pkg/cert"
	"auto-cert/pkg/ref"

	aliCdn "github.com/alibabacloud-go/cdn-20180510/v5/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
)

type Client struct {
	c *aliCdn.Client
}

type CertInfo struct {
	DomainName string
	Name       string
	ExpireTime time.Time
	StartTime  time.Time
	Enabled    bool
	Id         string
	Type       string
	Region     string
}

func CreateClient(cfg *openapi.Config) (*Client, error) {
	c, err := aliCdn.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{c}, nil
}

var (
	ErrDomainEmpty = errors.New("domain is empty")
)

const (
	statusOn  = "on"
	statusOff = "off"
)

func (c *Client) QueryDomainCertificate(domain string) (*CertInfo, error) {
	if domain == "" {
		return nil, ErrDomainEmpty
	}
	req := &aliCdn.DescribeDomainCertificateInfoRequest{
		DomainName: ref.GetPointer(domain),
	}

	res, err := c.c.DescribeDomainCertificateInfoWithOptions(req, &util.RuntimeOptions{})
	if err != nil {
		return nil, err
	}

	var certInfo *aliCdn.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo
	for _, cert := range res.Body.CertInfos.CertInfo {
		if ref.DerefOrDefault(cert.DomainName) == domain {
			certInfo = cert
			break
		}
	}
	ci := &CertInfo{
		DomainName: ref.DerefOrDefault(certInfo.DomainName),
		Name:       ref.DerefOrDefault(certInfo.CertName),
		Enabled:    ref.DerefOr(certInfo.ServerCertificateStatus, statusOff) == statusOn,
		Id:         ref.DerefOrDefault(certInfo.CertId),
		Type:       ref.DerefOrDefault(certInfo.CertType),
		Region:     ref.DerefOrDefault(certInfo.CertRegion),
	}
	// format: 2018-06-03T22:03:39Z
	ci.ExpireTime, err = time.Parse(time.RFC3339, ref.DerefOrDefault(certInfo.CertExpireTime))
	if err != nil {
		return nil, err
	}

	ci.StartTime, err = time.Parse(time.RFC3339, ref.DerefOrDefault(certInfo.CertStartTime))
	if err != nil {
		return nil, err
	}

	return ci, nil
}

type SetCertOption func(*aliCdn.SetCdnDomainSSLCertificateRequest) error

func SetCertWithEnable(enable bool) SetCertOption {
	return func(req *aliCdn.SetCdnDomainSSLCertificateRequest) error {
		status := statusOff
		if enable {
			status = statusOn
		}
		req.SSLProtocol = ref.GetPointer(status)
		return nil
	}
}

type CertType string

const (
	CertUpload CertType = "upload"
	CertCas    CertType = "cas"
)

func SetCertWithCertType(certType CertType) SetCertOption {
	return func(req *aliCdn.SetCdnDomainSSLCertificateRequest) error {
		req.SSLProtocol = ref.GetPointer(string(certType))
		return nil
	}
}

func (c *Client) SetCert(domain string, cert *cert.Cert, options ...SetCertOption) error {
	req := &aliCdn.SetCdnDomainSSLCertificateRequest{
		DomainName: ref.GetPointer(domain),
		// default options
		SSLProtocol: ref.GetPointer(statusOn),
		CertType:    ref.GetPointer(string(CertUpload)),
	}

	for _, opt := range options {
		if err := opt(req); err != nil {
			return err
		}
	}

	// set cert
	sslPub, sslPri, err := cert.GeneratePemEncoded()
	if err != nil {
		return err
	}
	if cert != nil {
		req.SSLPub = ref.GetPointer(string(sslPub))
		req.SSLPri = ref.GetPointer(string(sslPri))
	}

	_, err = c.c.SetCdnDomainSSLCertificateWithOptions(req, &util.RuntimeOptions{})

	return err
}
