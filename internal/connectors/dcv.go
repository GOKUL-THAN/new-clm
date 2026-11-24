package connectors

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

type DCVType string

const (
	DCVHTTP01    DCVType = "http-01"
	DCVDNS01     DCVType = "dns-01"
	DCVTLSALPN01 DCVType = "tls-alpn-01"
)

type DCVChallenge struct {
	Type        DCVType `json:"type"`
	Domain      string  `json:"domain"`
	Token       string  `json:"token"`
	KeyAuth     string  `json:"key_auth"`
	DNSResource string  `json:"dns_resource,omitempty"` // _acme-challenge.<domain>
	DNSValue    string  `json:"dns_value,omitempty"`    // base64url(sha256(key_auth))
	HTTPPath    string  `json:"http_path,omitempty"`    // /.well-known/acme-challenge/<token>
}

type DCVEngine struct {
	delegatedValidationZone string
}

func NewDCVEngine(delegatedValidationZone string) *DCVEngine {
	return &DCVEngine{
		delegatedValidationZone: delegatedValidationZone,
	}
}

// GenerateDNS01Challenge creates the expected TXT record details, supporting CNAME delegation.
func (d *DCVEngine) GenerateDNS01Challenge(domain, token, accountKeyThumbprint string) *DCVChallenge {
	keyAuth := fmt.Sprintf("%s.%s", token, accountKeyThumbprint)
	hash := sha256.Sum256([]byte(keyAuth))
	dnsValue := base64.RawURLEncoding.EncodeToString(hash[:])

	recordName := fmt.Sprintf("_acme-challenge.%s", domain)
	if d.delegatedValidationZone != "" {
		// CNAME delegation mode (README Sec 14)
		// e.g. _acme-challenge.app.example.com -> app.example.com.validation.corp.example.net
		recordName = fmt.Sprintf("%s.%s", domain, strings.TrimPrefix(d.delegatedValidationZone, "."))
	}

	return &DCVChallenge{
		Type:        DCVDNS01,
		Domain:      domain,
		Token:       token,
		KeyAuth:     keyAuth,
		DNSResource: recordName,
		DNSValue:    dnsValue,
	}
}

// GenerateHTTP01Challenge creates the expected HTTP URL and payload.
func (d *DCVEngine) GenerateHTTP01Challenge(domain, token, accountKeyThumbprint string) *DCVChallenge {
	keyAuth := fmt.Sprintf("%s.%s", token, accountKeyThumbprint)
	return &DCVChallenge{
		Type:     DCVHTTP01,
		Domain:   domain,
		Token:    token,
		KeyAuth:  keyAuth,
		HTTPPath: fmt.Sprintf("/.well-known/acme-challenge/%s", token),
	}
}

// CheckCAA verifies if the chosen CA is permitted by CAA records (RFC 8659).
func (d *DCVEngine) CheckCAA(domain, allowedCA string, mockCAARecords map[string][]string) (bool, string) {
	// Look up CAA for domain or parent domain
	records, ok := mockCAARecords[domain]
	if !ok {
		// No CAA record means any CA is permitted
		return true, "no CAA restriction found (permitted)"
	}

	for _, rec := range records {
		parts := strings.Fields(rec)
		var tag, value string
		if len(parts) >= 3 {
			tag = strings.ToLower(parts[1])
			value = strings.Trim(parts[2], `"`)
		} else if len(parts) == 2 {
			tag = strings.ToLower(parts[0])
			value = strings.Trim(parts[1], `"`)
		} else {
			continue
		}

		if (tag == "issue" || tag == "issuewild") && strings.Contains(value, allowedCA) {
			return true, fmt.Sprintf("CAA tag '%s' explicitly authorizes '%s'", tag, allowedCA)
		}
	}

	return false, fmt.Sprintf("CAA records for '%s' do not authorize CA '%s'", domain, allowedCA)
}
