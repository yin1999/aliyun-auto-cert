package main

import (
	"auto-cert/pkg/cdn"
	"auto-cert/pkg/cert"
	"auto-cert/pkg/dns"
	"auto-cert/pkg/ref"
	"auto-cert/pkg/tld"
	"context"
	"flag"
	"fmt"
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
	var (
		forceRenew        = false
		createAcmeAccount = false
	)
	flag.BoolVar(&forceRenew, "f", false, "force renew")
	flag.BoolVar(&createAcmeAccount, "a", false, "create acme account")

	fullDomain := mustLoadEnv("FULL_DOMAIN")
	accountPath := loadEnvOr("ACCOUNT_FILE", "./account.json")
	tldPlusOne := loadEnvOr("DOMAIN", "")
	mustLoadAccount := loadEnvOr("MUST_LOAD_ACCOUNT", "false") == "true"

	if createAcmeAccount {
		// check if account exists
		log.Println("creating acme account")
		acmeCli := cert.NewClient()
		err := createAndStoreAcmeAccount(context.Background(), acmeCli, accountPath)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

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

	ak := mustLoadEnv("ACCESS_KEY")
	secret := mustLoadEnv("ACCESS_SECRET")
	cfg := &openapi.Config{
		AccessKeyId:     ref.GetPointer(ak),
		AccessKeySecret: ref.GetPointer(secret),
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
		err = createAndStoreAcmeAccount(ctx, acmeCli, accountPath)
		if err != nil {
			log.Fatal(err)
		}
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

func createAndStoreAcmeAccount(ctx context.Context, acmeCli *cert.Client, accountPath string) error {
	err := acmeCli.RegisterAccount(ctx, mustLoadEnv("EMAIL"))
	if err != nil {
		return fmt.Errorf("register account failed: %w", err)
	}
	log.Print("account registered\n")
	log.Print("Storing account\n")
	data, err := acmeCli.ExportAccount(ctx)
	if err != nil {
		return fmt.Errorf("export account failed: %w", err)
	}
	err = os.WriteFile(accountPath, data, 0600)
	if err != nil {
		log.Printf("failed to store account, please store it manually, account content:\n%s\n", string(data))
		return fmt.Errorf("store account failed: %w", err)
	}
	log.Printf("account stored at %s\n", accountPath)
	return nil
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
