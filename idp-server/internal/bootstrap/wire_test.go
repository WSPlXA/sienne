package bootstrap

import "testing"

func TestResolveTOTPIssuerPrefersExplicitDisplayName(t *testing.T) {
	cfg := &config{
		Issuer:     "https://www.idpsienne.uk",
		TOTPIssuer: "IDP Sienne",
	}
	got := resolveTOTPIssuer(cfg)
	if got != "IDP Sienne" {
		t.Fatalf("resolveTOTPIssuer() = %q, want %q", got, "IDP Sienne")
	}
}

func TestResolveTOTPIssuerUsesIssuerHostAsFallback(t *testing.T) {
	cfg := &config{Issuer: "https://www.idpsienne.uk"}
	got := resolveTOTPIssuer(cfg)
	if got != "www.idpsienne.uk" {
		t.Fatalf("resolveTOTPIssuer() = %q, want %q", got, "www.idpsienne.uk")
	}
}

func TestResolveTOTPIssuerReturnsRawIssuerWhenNotURL(t *testing.T) {
	cfg := &config{Issuer: "IDP-SIENNE"}
	got := resolveTOTPIssuer(cfg)
	if got != "IDP-SIENNE" {
		t.Fatalf("resolveTOTPIssuer() = %q, want %q", got, "IDP-SIENNE")
	}
}
