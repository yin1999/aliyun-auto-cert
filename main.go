package main

import (
	"auto-cert/pkg/cdn"
	"auto-cert/pkg/cert"
	"auto-cert/pkg/dns"
	"auto-cert/pkg/ref"
	"auto-cert/pkg/tld"
	"context"
	"log"
	"os"
	"strings"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"golang.org/x/crypto/acme"
)

const (
	RenewBefore = 10 * 24 * time.Hour
)

func main() {
	ak := mustLoadEnv("ACCESS_KEY")
	secret := mustLoadEnv("ACCESS_SECRET")

	cfg := &openapi.Config{
		AccessKeyId:     ref.GetPointer(ak),
		AccessKeySecret: ref.GetPointer(secret),
	}
	fullDomain := mustLoadEnv("FULL_DOMAIN")
	accountPath := loadEnvOr("ACCOUNT_FILE", "./account.json")
	tldPlusOne := loadEnvOr("DOMAIN", "")
	mustLoadAccount := loadEnvOr("MUST_LOAD_ACCOUNT", "false") == "true"
	subDomain := ""
	if tldPlusOne == "" {
		tld, err := tld.ParseDomain(fullDomain)
		if err != nil {
			log.Fatalf("parse domain failed: %v", err)
		}
		tldPlusOne = tld.TLDPlusOne
		subDomain = tld.SubDomain
	} else {
		if !strings.HasSuffix(fullDomain, tldPlusOne) {
			log.Fatalf("full domain %q is not match with domain %q\n", fullDomain, tldPlusOne)
		}
		subDomain = fullDomain[:len(fullDomain)-len(tldPlusOne)-1]
		// now, the subDomain should be end with a dot or empty
		if subDomain != "" && !strings.HasSuffix(subDomain, ".") {
			log.Fatalf("full domain %q is not match with domain %q\n", fullDomain, tldPlusOne)
		}
		subDomain = strings.TrimSuffix(subDomain, ".")
	}

	cdnCli, err := cdn.CreateClient(cfg)
	if err != nil {
		log.Fatalf("create cdn client failed: %v", err)
	}

	// check domain's certificate
	certInfo, err := cdnCli.QueryDomainCertificate(fullDomain)
	if err != nil {
		log.Fatalf("query domain certificate failed: %v", err)
	}
	duration := time.Until(certInfo.ExpireTime)
	if duration > RenewBefore {
		log.Printf("certificate is not expired, skip renew")
		return
	}

	if duration <= 0 {
		log.Printf("certificate is expired, renew it")
	} else {
		log.Printf("certificate will be expired in %v, renew it", duration)
	}

	dnsCli, err := dns.CreateClient(cfg)
	if err != nil {
		log.Fatalf("create dns client failed: %v", err)
	}

	resolveDnsChallenge := func(ctx context.Context, ch *acme.Challenge, getToken cert.GetChallengeToken, accept cert.AcceptChallenge) error {
		if ch.Type != cert.AcmeChallengeDNS01 {
			return cert.ErrNotImplemented
		}

		rr := cert.GetDNS01ChallengeRecord(subDomain)
		value, err := getToken(ch.Token)
		if err != nil {
			return err
		}

		err = dnsCli.AddOrSetTextRecord(tldPlusOne, rr, value)
		if err != nil {
			return err
		}

		defer dnsCli.DeleteTextRecord(tldPlusOne, rr)

		// sleep for a while to make sure the record is effective
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}

		return accept(ctx)
	}

	acmeCli := cert.NewClient()
	ctx := context.Background()
	err = acmeCli.LoadAccount(ctx, accountPath)
	if err != nil {
		if mustLoadAccount {
			log.Fatalf("load account failed: %v", err)
		}
		log.Printf("account not found (%s), register it", err.Error())
		err = acmeCli.RegisterAccount(ctx, mustLoadEnv("EMAIL"))
		if err != nil {
			log.Fatalf("register account failed: %v", err)
		}
		log.Printf("account registered")
		log.Printf("Storing account")
		err = acmeCli.StoreAccount(ctx, accountPath)
		if err != nil {
			log.Fatalf("store account failed: %v", err)
		}
		log.Printf("account stored")
	}

	c, err := acmeCli.GenerateCert(ctx, fullDomain, cert.KeyECDSA, resolveDnsChallenge)
	if err != nil {
		log.Fatalf("generate certificate failed: %v", err)
	}

	// upload certificate
	err = cdnCli.SetCert(fullDomain, c)
	if err != nil {
		log.Fatalf("set certificate failed: %v", err)
	}
	log.Printf("certificate set")
}

func mustLoadEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("env %s is empty", key)
	}
	return v
}

func loadEnvOr(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}
