package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"auto-cert/pkg/cdn"
	"auto-cert/pkg/cert"
	"auto-cert/pkg/dns"
	"auto-cert/pkg/env"
	"auto-cert/pkg/ref"
	"auto-cert/pkg/tld"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"golang.org/x/crypto/acme"
)

const (
	RenewBefore = 10 * 24 * time.Hour
)

type config struct {
	email       string
	fullDomain  string
	tldPlusOne  string
	subDomain   string
	accountPath string

	accessKey    string
	accessSecret string
}

func main() {
	var (
		forceRenew        = false
		createAcmeAccount = false
		ctx               = context.Background()

		mustLoadAccount bool
	)
	cfg := &config{}
	flag.BoolVar(&forceRenew, "f", false, "force renew")
	flag.BoolVar(&createAcmeAccount, "a", false, "create acme account")
	flag.StringVar(&cfg.email, "e", env.GetString("EMAIL", ""), "email for acme account")
	flag.StringVar(&cfg.fullDomain, "fd", env.GetString("FULL_DOMAIN", ""), "the full domain to generate certificate")
	flag.StringVar(&cfg.tldPlusOne, "tp", env.GetString("TLD_PLUS_ONE", ""), "tld plus one")
	flag.StringVar(&cfg.accountPath, "ap", env.GetString("ACCOUNT_FILE", "./account.json"), "account file path, it can also be the environment variable (format: `env:ENV_NAME`) which contains the account information")
	flag.BoolVar(&mustLoadAccount, "m", env.GetBool("MUST_LOAD_ACCOUNT", false), "must load account")
	flag.StringVar(&cfg.accessKey, "ak", env.GetString("ACCESS_KEY", ""), "access key")
	flag.StringVar(&cfg.accessSecret, "sk", env.GetString("ACCESS_SECRET", ""), "access secret")

	if cfg.email == "" {
		log.Fatal("email is empty")
	}
	if createAcmeAccount {
		// check if account exists
		acmeCli := cert.NewClient()
		if err := acmeCli.LoadAccount(ctx, cfg.accountPath); err == nil {
			log.Print("acme account exists, skip creating acme account\n")
			return
		}

		log.Print("creating acme account\n")
		err := createAndStoreAcmeAccount(ctx, acmeCli, cfg)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	if cfg.fullDomain == "" {
		log.Fatal("full domain is empty")
	}
	cfg.subDomain = parseSubDomain(cfg)

	if cfg.accessKey == "" || cfg.accessSecret == "" {
		log.Fatal("access key or access secret is empty")
	}
	apiCfg := &openapi.Config{
		AccessKeyId:     ref.GetPointer(cfg.accessKey),
		AccessKeySecret: ref.GetPointer(cfg.accessSecret),
	}
	cdnCli, err := cdn.CreateClient(apiCfg)
	if err != nil {
		log.Fatalf("create cdn client failed: %v", err)
	}

	// check domain's certificate
	if !shouldRenewCert(cdnCli, forceRenew, cfg) {
		return
	}

	dnsCli, err := dns.CreateClient(apiCfg)
	if err != nil {
		log.Fatalf("create dns client failed: %v", err)
	}

	acmeCli := cert.NewClient()
	err = acmeCli.LoadAccount(ctx, cfg.accountPath)
	if err != nil {
		if mustLoadAccount {
			log.Fatalf("load account failed: %v", err)
		}
		log.Printf("account not found (%v), register it\n", err)
		err = createAndStoreAcmeAccount(ctx, acmeCli, cfg)
		if err != nil {
			log.Fatal(err)
		}
	}

	c, err := acmeCli.GenerateCert(ctx, cfg.fullDomain, cert.KeyECDSA, resolveDnsChallengeFunc(dnsCli, cfg))
	if err != nil {
		log.Fatalf("generate certificate failed: %v", err)
	}

	// upload certificate
	err = cdnCli.SetCert(cfg.fullDomain, c)
	if err != nil {
		log.Fatalf("set certificate failed: %v", err)
	}
	log.Print("certificate set\n")
}

func shouldRenewCert(cdnCli *cdn.Client, forceRenew bool, cfg *config) bool {
	if forceRenew {
		log.Print("force renew the certificate\n")
		return true
	}
	certInfo, err := cdnCli.QueryDomainCertificate(cfg.fullDomain)
	if err != nil {
		log.Fatalf("query domain certificate failed: %v", err)
	}
	duration := time.Until(certInfo.ExpireTime)
	if duration > RenewBefore {
		log.Print("certificate is not expired, skip renew\n")
		return false
	}

	if duration <= 0 {
		log.Print("certificate is expired, renew it\n")
	} else {
		log.Printf("certificate will be expired in %v, renew it\n", duration)
	}
	return true
}

func parseSubDomain(cfg *config) string {
	if cfg.tldPlusOne == "" {
		tld, err := tld.ParseDomain(cfg.fullDomain)
		if err != nil {
			log.Fatalf("parse domain failed: %v", err)
		}
		cfg.tldPlusOne = tld.TLDPlusOne
		return tld.SubDomain
	}

	if !strings.HasSuffix(cfg.fullDomain, cfg.tldPlusOne) {
		log.Fatalf("full domain %q is not match with domain %q", cfg.fullDomain, cfg.tldPlusOne)
	}
	subDomain := cfg.fullDomain[:len(cfg.fullDomain)-len(cfg.tldPlusOne)-1]
	// now, the subDomain should be end with a dot or empty
	if subDomain != "" && !strings.HasSuffix(subDomain, ".") {
		log.Fatalf("full domain %q is not match with domain %q", cfg.fullDomain, cfg.tldPlusOne)
	}
	return strings.TrimSuffix(subDomain, ".")
}

func resolveDnsChallengeFunc(dnsCli *dns.Client, cfg *config) func(ctx context.Context, ch *acme.Challenge, getToken cert.GetChallengeToken, accept cert.AcceptChallenge) error {
	return func(ctx context.Context, ch *acme.Challenge, getToken cert.GetChallengeToken, accept cert.AcceptChallenge) error {
		if ch.Type != cert.AcmeChallengeDNS01 {
			return cert.ErrNotImplemented
		}

		rr := cert.GetDNS01ChallengeRecord(cfg.subDomain)
		value, err := getToken(ch.Token)
		if err != nil {
			return err
		}

		err = dnsCli.AddOrSetTextRecord(cfg.tldPlusOne, rr, value)
		if err != nil {
			return err
		}

		defer dnsCli.DeleteTextRecord(cfg.tldPlusOne, rr)

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
}

func createAndStoreAcmeAccount(ctx context.Context, acmeCli *cert.Client, cfg *config) error {
	err := acmeCli.RegisterAccount(ctx, cfg.email)
	if err != nil {
		return fmt.Errorf("register account failed: %w", err)
	}
	log.Print("account registered\n")
	log.Print("Storing account\n")
	data, err := acmeCli.ExportAccount(ctx)
	if err != nil {
		return fmt.Errorf("export account failed: %w", err)
	}
	err = os.WriteFile(cfg.accountPath, data, 0600)
	if err != nil {
		log.Printf("failed to store account, please store it manually, account content:\n%s\n", string(data))
		return fmt.Errorf("store account failed: %w", err)
	}
	log.Printf("account stored at %s\n", cfg.accountPath)
	return nil
}
