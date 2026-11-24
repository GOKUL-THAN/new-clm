package inventory

import (
	"encoding/json"
	"strings"
	"time"

	"clm/internal/models"
)

// CBOM represents a Cryptographic Bill of Materials following CycloneDX conventions.
type CBOM struct {
	BOMFormat    string                 `json:"bomFormat"`
	SpecVersion  string                 `json:"specVersion"`
	SerialNumber string                 `json:"serialNumber"`
	Version      int                    `json:"version"`
	Metadata     CBOMMetadata           `json:"metadata"`
	Components   []CBOMCryptoComponent  `json:"components"`
}

type CBOMMetadata struct {
	Timestamp string `json:"timestamp"`
	Author    string `json:"author"`
	Tool      string `json:"tool"`
}

type CBOMCryptoComponent struct {
	Type               string             `json:"type"` // cryptographic-asset
	Name               string             `json:"name"`
	Description        string             `json:"description"`
	CryptoProperties   CryptoProperties   `json:"cryptoProperties"`
}

type CryptoProperties struct {
	AssetType            string `json:"assetType"` // certificate, algorithm, protocol
	Algorithm            string `json:"algorithm"`
	KeyLength            int    `json:"keyLength,omitempty"`
	Fingerprint          string `json:"fingerprint,omitempty"`
	NotAfter             string `json:"notAfter,omitempty"`
	Issuer               string `json:"issuer,omitempty"`
	QuantumVulnerable    bool   `json:"quantumVulnerable"`
	PQCReadiness         string `json:"pqcReadiness"` // vulnerable, hybrid, post-quantum
}

// GenerateCBOM builds a Cryptographic Bill of Materials from an inventory of certificates.
func GenerateCBOM(tenantID string, certs []*models.Certificate) (*CBOM, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	cbom := &CBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:cbom-" + tenantID,
		Version:      1,
		Metadata: CBOMMetadata{
			Timestamp: now,
			Author:    "CLM Platform",
			Tool:      "clm-crypto-agility-engine",
		},
		Components: make([]CBOMCryptoComponent, 0, len(certs)),
	}

	for _, cert := range certs {
		upperAlg := strings.ToUpper(cert.KeyAlgorithm)

		// Post-quantum status: RSA and classic ECC are vulnerable (Sec 31)
		isQV := true
		pqcStatus := "vulnerable"
		if strings.Contains(upperAlg, "ML-DSA") || strings.Contains(upperAlg, "SLH-DSA") || strings.Contains(upperAlg, "PQC") {
			isQV = false
			pqcStatus = "post-quantum"
		} else if strings.Contains(upperAlg, "HYBRID") {
			isQV = false
			pqcStatus = "hybrid"
		}

		comp := CBOMCryptoComponent{
			Type:        "cryptographic-asset",
			Name:        cert.SubjectDN,
			Description: "X.509 Certificate Asset",
			CryptoProperties: CryptoProperties{
				AssetType:         "certificate",
				Algorithm:         cert.KeyAlgorithm,
				KeyLength:         cert.KeyBits,
				Fingerprint:       cert.FingerprintSHA256,
				NotAfter:          cert.NotAfter.Format(time.RFC3339),
				Issuer:            cert.IssuerDN,
				QuantumVulnerable: isQV,
				PQCReadiness:      pqcStatus,
			},
		}
		cbom.Components = append(cbom.Components, comp)
	}

	return cbom, nil
}

func (c *CBOM) ToJSON() (string, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
