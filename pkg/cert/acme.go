package cert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"auto-cert/pkg/tld"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Client struct {
	cache autocert.DirCache
	c     acme.Client
}

type RenewalInfoWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type RenewInfo struct {
	SuggestedWindow RenewalInfoWindow `json:"suggestedWindow"`
	ExplanationURL  string            `json:"explanationURL"`
}

const (
	AccountKey = "account"

	AcmeChallengeDNS01  = "dns-01"
	AcmeChallengeHTTP01 = "http-01"
)

type accountInfo struct {
	Key privateKeyWrapper `json:"key"`
	Kid acme.KeyID        `json:"kid"`
}

type privateKeyWrapper ecdsa.PrivateKey

var _ encoding.TextMarshaler = privateKeyWrapper{}
var _ encoding.TextUnmarshaler = &privateKeyWrapper{}

func (a *privateKeyWrapper) UnmarshalText(b []byte) error {
	block, rest := pem.Decode(b)
	if len(rest) > 0 {
		return errors.New("extra data after PEM block")
	}
	if block == nil {
		return errors.New("no PEM block found")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	*a = privateKeyWrapper(*key)
	return nil
}

func (a privateKeyWrapper) MarshalText() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey((*ecdsa.PrivateKey)(&a))
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}), nil
}

func generateKey(keyType KeyType) (k crypto.Signer, der []byte, err error) {
	switch keyType {
	case KeyRSA:
		var sk *rsa.PrivateKey
		sk, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return
		}
		k = sk
		der = x509.MarshalPKCS1PrivateKey(sk)
	case KeyECDSA:
		var sk *ecdsa.PrivateKey
		sk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return
		}
		der, err = x509.MarshalECPrivateKey(sk)
		if err == nil {
			k = sk
		}
	default:
		return nil, nil, errors.New("unsupported key type")
	}
	if err != nil {
		return nil, nil, err
	}
	return
}

type ClientOption func(c *Client)

func SetDirectoryURL(url string) ClientOption {
	return func(c *Client) {
		c.c.DirectoryURL = url
	}
}

func NewClient(options ...ClientOption) *Client {
	c := &Client{
		c: acme.Client{
			DirectoryURL: acme.LetsEncryptURL,
		},
	}
	for _, opt := range options {
		opt(c)
	}
	return c
}

// LoadAccount loads the account information from the file or environment
// to load the account from the environment, the file should be in the format:
// `env:ENV_NAME`
func (c *Client) LoadAccount(ctx context.Context, file string) error {
	var reader io.Reader
	if strings.HasPrefix(file, "env:") {
		env := strings.TrimPrefix(file, "env:")
		v := os.Getenv(env)
		if v == "" {
			return fmt.Errorf("env %q is empty", env)
		}
		reader = bytes.NewBufferString(v)
	} else {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		reader = f
	}

	account := accountInfo{}
	err := json.NewDecoder(reader).Decode(&account)
	if err != nil {
		return err
	}

	if account.Kid == "" {
		return errors.New("missing account kid")
	}

	c.c.Key = (*ecdsa.PrivateKey)(&account.Key)
	c.c.KID = account.Kid

	return nil
}

func (c *Client) AccountKeyRollover(ctx context.Context) error {
	priv, _, err := generateKey(KeyECDSA)
	if err != nil {
		return err
	}
	return c.c.AccountKeyRollover(ctx, priv)
}

// ExportAccount export the account information to bytes in JSON format
func (c *Client) ExportAccount(ctx context.Context) ([]byte, error) {
	key, ok := c.c.Key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("unsupported key type")
	}

	account := accountInfo{
		Key: privateKeyWrapper(*key),
		Kid: c.c.KID,
	}

	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")

	if err := enc.Encode(account); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Client) RegisterAccount(ctx context.Context, email string) error {
	priv, _, err := generateKey(KeyECDSA)
	if err != nil {
		return err
	}
	c.c.Key = priv

	account, err := c.c.Register(ctx, &acme.Account{
		Contact: []string{"mailto:" + email},
	}, acme.AcceptTOS)
	if err != nil {
		return err
	}
	// the KID will be set by Register
	log.Printf("registered account %s", account.URI)
	return nil
}

func (c *Client) DeleteAccountCache(ctx context.Context) error {
	return c.cache.Delete(ctx, AccountKey)
}

func (c *Client) UnregisterAccount(ctx context.Context) error {
	return c.c.DeactivateReg(ctx)
}

type GetChallengeToken func(token string) (string, error)
type AcceptChallenge func(ctx context.Context) error
type ProcessChallenge func(ctx context.Context, ch *acme.Challenge, getToken GetChallengeToken, accept AcceptChallenge) error

var (
	ErrNotImplemented = errors.New("not implemented")
)

func GetDNS01ChallengeRecord(subDomain string) string {
	if subDomain == "" || subDomain == tld.PrimaryDomain {
		return "_acme-challenge"
	}
	return "_acme-challenge." + subDomain
}

func GetHTTP01ChallengePath(token string) string {
	return "/.well-known/acme-challenge/" + token
}

func (c *Client) GetRenewInfo(ctx context.Context, leaf *x509.Certificate) (*RenewInfo, error) {
	ariCertId, err := makeARICertID(leaf)
	if err != nil {
		return nil, err
	}

	directory, err := c.c.Discover(ctx)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(directory.RenewalInfo)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, ariCertId)
	resp, err := c.c.HTTPClient.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ri := &RenewInfo{}
	if err := json.NewDecoder(resp.Body).Decode(&ri); err != nil {
		return nil, err
	}
	return ri, nil
}

// ref: https://letsencrypt.org/2024/04/25/guide-to-integrating-ari-into-existing-acme-clients/#step-3-constructing-the-ari-certid
func makeARICertID(leaf *x509.Certificate) (string, error) {
	if leaf == nil {
		return "", errors.New("leaf certificate is nil")
	}

	// Marshal the Serial Number into DER.
	der, err := asn1.Marshal(leaf.SerialNumber)
	if err != nil {
		return "", err
	}

	// Check if the DER encoded bytes are sufficient (at least 3 bytes: tag,
	// length, and value).
	if len(der) < 3 {
		return "", errors.New("invalid DER encoding of serial number")
	}

	// Extract only the integer bytes from the DER encoded Serial Number
	// Skipping the first 2 bytes (tag and length). The result is base64url
	// encoded without padding.
	serial := base64.RawURLEncoding.EncodeToString(der[2:])

	// Convert the Authority Key Identifier to base64url encoding without
	// padding.
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)

	// Construct the final identifier by concatenating AKI and Serial Number.
	return fmt.Sprintf("%s.%s", aki, serial), nil
}

func (c *Client) GenerateCert(ctx context.Context, domain string, keyType KeyType, processChallenge ProcessChallenge) (ce *Cert, err error) {
	if processChallenge == nil {
		return nil, errors.New("processChallenge is required")
	}
	s, privDer, err := generateKey(keyType)
	if err != nil {
		return nil, err
	}

	certReq := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames: []string{domain},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &certReq, s)
	if err != nil {
		return nil, err
	}

	order, err := c.c.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, err
	}

	defer c.deactivatePendingAuthz(ctx, order.AuthzURLs)

	// resolve challenges
	err = c.resolveChallenge(ctx, order, processChallenge)
	if err != nil {
		return nil, err
	}

	der, _, err := c.c.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, err
	}

	x509Certs, err := decodeCert(der)
	if err != nil {
		return nil, err
	}
	if len(x509Certs) == 0 {
		return nil, errors.New("no certificates returned")
	}

	leaf := x509Certs[0]
	if err = validCert(leaf, domain, s, time.Now()); err != nil {
		return nil, err
	}

	return &Cert{
		keyType:    keyType,
		publicKeys: der,
		privateKey: privDer,
	}, nil
}

func (c *Client) deactivatePendingAuthz(ctx context.Context, authzURLs []string) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for _, u := range authzURLs {
		z, err := c.c.GetAuthorization(ctx, u)
		if err == nil && z.Status == acme.StatusPending {
			c.c.RevokeAuthorization(ctx, u)
		}
	}
}

func decodeCert(der [][]byte) ([]*x509.Certificate, error) {
	n := 0
	for _, b := range der {
		n += len(b)
	}
	pub := make([]byte, n)
	n = 0
	for _, b := range der {
		n += copy(pub[n:], b)
	}
	x509Cert, err := x509.ParseCertificates(pub)
	if err != nil {
		return nil, err
	}
	return x509Cert, nil
}

func validCert(leaf *x509.Certificate, domain string, key crypto.PrivateKey, now time.Time) error {
	if now.Before(leaf.NotBefore) {
		return errors.New("acme/autocert: certificate is not valid yet")
	}
	if now.After(leaf.NotAfter) {
		return errors.New("acme/autocert: expired certificate")
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return err
	}
	// ensure the leaf corresponds to the private key and matches the certKey type
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.N.Cmp(prv.N) != 0 {
			return errors.New("acme/autocert: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		prv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			return errors.New("acme/autocert: private key does not match public key")
		}
	default:
		return errors.New("acme/autocert: unknown public key algorithm")
	}
	return nil
}

func (c *Client) resolveChallenge(ctx context.Context, order *acme.Order, processChallenge ProcessChallenge) error {
	for _, authzURL := range order.AuthzURLs {
		authz, err := c.c.GetAuthorization(ctx, authzURL)
		if err != nil {
			return err
		}
		success := false
		for _, ch := range authz.Challenges {
			if ch.Status == acme.StatusValid {
				success = true
				break
			}
			accept := func(ctx context.Context) error {
				_, err := c.c.Accept(ctx, ch)
				if err != nil {
					return err
				}

				// wait for challenge to be ready
				// try three times
				var timer *time.Timer
				for i := 0; i < 3; i++ {
					log.Printf("waiting for challenge to be ready (%d/%d)", i+1, 3)
					_, err = c.c.WaitAuthorization(ctx, authzURL)
					if err == nil {
						log.Printf("challenge is ready")
						break
					}
					log.Printf("challenge is not ready, retrying in 5 seconds: %v", err)
					if timer == nil {
						timer = time.NewTimer(5 * time.Second)
					}
					select {
					case <-timer.C:
					case <-ctx.Done():
						timer.Stop()
						return ctx.Err()
					}
				}
				success = err == nil
				return err
			}
			var err error
			if ch.Type == AcmeChallengeDNS01 {
				err = processChallenge(ctx, ch, c.c.DNS01ChallengeRecord, accept)
			} else if ch.Type == AcmeChallengeHTTP01 {
				err = processChallenge(ctx, ch, c.c.HTTP01ChallengeResponse, accept)
			} else {
				err = ErrNotImplemented
			}
			if err == ErrNotImplemented {
				continue
			}
			if err != nil {
				return err
			}
			break
		}
		if !success {
			return errors.New("no accepted challenge")
		}
	}
	_, err := c.c.WaitOrder(ctx, order.URI)
	return err
}
