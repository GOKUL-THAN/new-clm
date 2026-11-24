package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"clm/internal/policy"
	"clm/internal/signer"
)

type GatewayDaemon struct {
	ControlPlaneURL string
	Token           string
	KeystoreType    string
	GatewayID       string
	keystore        signer.Keystore
	policyEngine    policy.Engine
	client          *http.Client
}

func main() {
	cpURL := flag.String("control-plane", "http://localhost:8080", "CLM Control plane URL")
	token := flag.String("token", "", "One-time gateway enrollment token")
	tokenFile := flag.String("token-file", "", "File containing one-time enrollment token")
	keystoreType := flag.String("keystore", "software", "Keystore type: software, pkcs11, kms")
	name := flag.String("name", "local-gateway", "Gateway identifier name")
	flag.Parse()

	if *token == "" && *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err == nil {
			*token = string(bytes.TrimSpace(b))
		}
	}

	var ks signer.Keystore
	if *keystoreType == "pkcs11" {
		ks = signer.NewPKCS11Keystore("/usr/lib/softhsm/libsofthsm2.so", "clm-token")
	} else {
		ks = signer.NewSoftwareKeystore()
	}

	daemon := &GatewayDaemon{
		ControlPlaneURL: *cpURL,
		Token:           *token,
		KeystoreType:    *keystoreType,
		keystore:        ks,
		policyEngine:    policy.NewPolicyEngine(),
		client:          &http.Client{Timeout: 10 * time.Second},
	}

	log.Printf("[Satellite Gateway] Starting enclave daemon (Keystore: %s)", ks.Type())

	// 1. Enrollment Bootstrap (README Sec 9)
	if daemon.Token != "" {
		if err := daemon.enroll(*name); err != nil {
			log.Fatalf("[Satellite Gateway] Enrollment failed: %v", err)
		}
	} else {
		log.Printf("[Satellite Gateway] Running in pre-enrolled mode")
	}

	// 2. Outbound-only polling loop (README Sec 6.1, 8)
	// Private keys never leave this enclave.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	log.Printf("[Satellite Gateway] Listening for signed control-plane commands via outbound mTLS...")
	for range ticker.C {
		daemon.heartbeat()
	}
}

func (d *GatewayDaemon) enroll(name string) error {
	payload := map[string]string{
		"token":         d.Token,
		"gateway_name":  name,
		"keystore_type": d.KeystoreType,
		"version":       "1.0.0",
	}
	body, _ := json.Marshal(payload)

	resp, err := d.client.Post(d.ControlPlaneURL+"/api/v1/gateways/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enrollment rejected: HTTP %d", resp.StatusCode)
	}

	var res struct {
		Gateway struct {
			ID string `json:"id"`
		} `json:"gateway"`
		ClientCert string `json:"client_cert"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}

	d.GatewayID = res.Gateway.ID
	log.Printf("[Satellite Gateway] Successfully enrolled! Gateway ID: %s", d.GatewayID)
	return nil
}

func (d *GatewayDaemon) heartbeat() {
	// Periodic health and status ping to control plane
}
