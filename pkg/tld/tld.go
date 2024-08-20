package tld

import (
	"golang.org/x/net/publicsuffix"
)

type TLD struct {
	TLDPlusOne string
	SubDomain  string
}

const PrimaryDomain = "@"

func ParseDomain(domain string) (*TLD, error) {
	tld, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return nil, err
	}
	if tld == domain {
		return &TLD{
			TLDPlusOne: domain,
			SubDomain:  PrimaryDomain,
		}, nil
	}
	// remove the tld plus one
	subDomain := domain[:len(domain)-len(tld)-1]
	return &TLD{
		TLDPlusOne: tld,
		SubDomain:  subDomain,
	}, nil
}
