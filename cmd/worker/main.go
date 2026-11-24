package main

import (
	"log"
	"os"
	"strings"
	"time"

	"clm/internal/connectors"
	"clm/internal/models"
	"clm/internal/policy"
	"clm/internal/storage"
	"clm/internal/workflow"
)

func main() {
	dbDriver := "sqlite"
	dbDSN := os.Getenv("CLM_DATABASE_URL")
	if strings.HasPrefix(dbDSN, "postgres://") || strings.HasPrefix(dbDSN, "postgresql://") {
		dbDriver = "postgres"
	} else if dbDSN == "" {
		dbDSN = "clm.db"
	}

	st, err := storage.NewSQLStorage(dbDriver, dbDSN)
	if err != nil {
		log.Fatalf("Worker storage init failed: %v", err)
	}
	defer st.Close()

	ca, err := connectors.NewBuiltinPrivateCA("CLM Enterprise Root CA")
	if err != nil {
		log.Fatalf("Worker CA init failed: %v", err)
	}

	pol := policy.NewPolicyEngine()
	wf := workflow.NewWorkflowEngine(st, pol, ca)

	log.Printf("[CLM Background Worker] Running automated renewal and discovery orchestrator...")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		tenants, err := st.ListTenants()
		if err != nil {
			continue
		}

		for _, t := range tenants {
			checkRenewals(st, wf, t.ID)
		}
	}
}

// checkRenewals inspects certificates nearing expiry and triggers zero-touch renewal (README Sec 4, 12).
func checkRenewals(st storage.Storage, wf *workflow.WorkflowEngine, tenantID string) {
	// Look for certs expiring within 30 days
	expiring, err := st.ListExpiringCertificates(tenantID, 30)
	if err != nil || len(expiring) == 0 {
		return
	}

	for _, cert := range expiring {
		if !cert.AutoRenew {
			continue
		}

		log.Printf("[Renewal Worker] Certificate %s (%s) is due for renewal (expires in %v)",
			cert.ID, cert.SubjectDN, time.Until(cert.NotAfter).Round(time.Hour))

		// Create renewal request
		renewReq := &models.CertificateRequest{
			TenantID:      tenantID,
			ProfileID:     cert.ProfileID,
			EnvironmentID: cert.EnvironmentID,
			CommonName:    cert.SubjectDN,
			SANs:          cert.SANs,
			KeyAlgorithm:  cert.KeyAlgorithm,
			KeyBits:       cert.KeyBits,
			Owner:         cert.Owner,
			Team:          cert.Team,
			Requester:     "clm-automated-renewal-worker",
		}

		if err := st.CreateCertificateRequest(renewReq); err != nil {
			log.Printf("[Renewal Worker] Failed to queue renewal request: %v", err)
			continue
		}

		// Process renewal request
		newCert, err := wf.ProcessRequest(renewReq.ID, tenantID)
		if err != nil {
			log.Printf("[Renewal Worker] Automated renewal for %s deferred: %v", cert.ID, err)
			continue
		}

		log.Printf("[Renewal Worker] Successfully renewed certificate %s -> New Cert %s", cert.ID, newCert.ID)
	}
}
