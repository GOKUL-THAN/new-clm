package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"clm/internal/audit"
	"clm/internal/connectors"
	"clm/internal/inventory"
	"clm/internal/models"
	"clm/internal/policy"
	"clm/internal/storage"
	"clm/internal/workflow"

	"github.com/google/uuid"
)

type Server struct {
	storage      storage.Storage
	policyEngine policy.Engine
	caConnector  connectors.Connector
	workflow     *workflow.WorkflowEngine
	discovery    *inventory.NetworkScanner
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbDriver := "sqlite"
	dbDSN := os.Getenv("CLM_DATABASE_URL")
	if strings.HasPrefix(dbDSN, "postgres://") || strings.HasPrefix(dbDSN, "postgresql://") {
		dbDriver = "postgres"
	} else if dbDSN == "" {
		dbDSN = "clm.db"
	}

	st, err := storage.NewSQLStorage(dbDriver, dbDSN)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer st.Close()

	ca, err := connectors.NewBuiltinPrivateCA("CLM Enterprise Root CA")
	if err != nil {
		log.Fatalf("Failed to initialize CA: %v", err)
	}

	pol := policy.NewPolicyEngine()
	wf := workflow.NewWorkflowEngine(st, pol, ca)
	disc := inventory.NewNetworkScanner(5 * time.Second)

	srv := &Server{
		storage:      st,
		policyEngine: pol,
		caConnector:  ca,
		workflow:     wf,
		discovery:    disc,
	}

	// Seed default data if needed
	srv.seedDefaults()

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	addr := ":" + port
	log.Printf("Starting CLM Control Plane on %s (DB: %s)", addr, dbDriver)
	if err := http.ListenAndServe(addr, srv.corsMiddleware(mux)); err != nil {
		log.Fatalf("Server stopped: %v", err)
	}
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, Idempotency-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) getTenantID(r *http.Request) string {
	tid := r.Header.Get("X-Tenant-ID")
	if tid != "" {
		return tid
	}
	tid = r.URL.Query().Get("tenant_id")
	if tid != "" {
		return tid
	}
	return "tenant_default"
}

func (s *Server) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, status int, title, detail string) {
	s.jsonResponse(w, status, map[string]interface{}{
		"type":   "about:blank",
		"title":  title,
		"status": status,
		"detail": detail,
	})
}

func (s *Server) seedDefaults() {
	tenants, _ := s.storage.ListTenants()
	if len(tenants) == 0 {
		defTenant := &models.Tenant{
			ID:     "tenant_default",
			Name:   "Acme Global",
			Slug:   "acme-global",
			Status: "active",
		}
		_ = s.storage.CreateTenant(defTenant)

		defEnv := &models.Environment{
			ID:       "env_aws_prod",
			TenantID: defTenant.ID,
			Name:     "aws-prod",
			Type:     "aws",
			Region:   "us-east-1",
			Tags:     []string{"production", "pci-dss"},
		}
		_ = s.storage.CreateEnvironment(defEnv)

		defProf := &models.CertificateProfile{
			ID:                   "prof_web_tls",
			TenantID:             defTenant.ID,
			Name:                 "prod-web-tls",
			Description:          "Production TLS server certificate with mandatory approval and 90-day max validity",
			AllowedCAs:           []string{"CLM Enterprise Root CA", "Let's Encrypt", "DigiCert"},
			Algorithms:           []string{"RSA-2048", "RSA-3072", "ECDSA-P256", "ECDSA-P384"},
			ValidityDaysMax:      90,
			AllowedSANPatterns:   []string{".acme.com", ".acme.internal"},
			AllowWildcards:       true,
			RequireApproval:      true,
			ApproverRoles:        []string{"security-team", "pki-admin"},
			RenewalThresholdDays: 30,
			CAAEnforce:           true,
		}
		_ = s.storage.CreateProfile(defProf)

		defTarget := &models.DeploymentTarget{
			ID:            "tgt_prod_lb",
			TenantID:      defTenant.ID,
			EnvironmentID: defEnv.ID,
			Name:          "prod-edge-lb",
			Type:          "nginx",
			HostAddress:   "10.0.1.10",
			Port:          443,
		}
		_ = s.storage.CreateDeploymentTarget(defTarget)
	}
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Health & OpenAPI
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		s.jsonResponse(w, http.StatusOK, map[string]string{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   "1.0.0",
		})
	})

	mux.HandleFunc("/api/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile("api/openapi.json")
		if err != nil {
			s.jsonError(w, http.StatusNotFound, "Not Found", "OpenAPI spec not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})

	// Tenants
	mux.HandleFunc("/api/v1/tenants", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			tenants, err := s.storage.ListTenants()
			if err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusOK, tenants)
			return
		}
		if r.Method == http.MethodPost {
			var t models.Tenant
			if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
				s.jsonError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
				return
			}
			if err := s.storage.CreateTenant(&t); err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusCreated, t)
			return
		}
	})

	// Environments
	mux.HandleFunc("/api/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		if r.Method == http.MethodGet {
			envs, err := s.storage.ListEnvironments(tenantID)
			if err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusOK, envs)
			return
		}
		if r.Method == http.MethodPost {
			var env models.Environment
			if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
				s.jsonError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
				return
			}
			env.TenantID = tenantID
			if err := s.storage.CreateEnvironment(&env); err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusCreated, env)
			return
		}
	})

	// Gateways & Enrollment
	mux.HandleFunc("/api/v1/gateways", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		gateways, err := s.storage.ListGateways(tenantID)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
			return
		}
		s.jsonResponse(w, http.StatusOK, gateways)
	})

	mux.HandleFunc("/api/v1/gateways/enrollment-tokens", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		if r.Method != http.MethodPost {
			s.jsonError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST required")
			return
		}
		var tok models.EnrollmentToken
		_ = json.NewDecoder(r.Body).Decode(&tok)
		tok.TenantID = tenantID
		if err := s.storage.CreateEnrollmentToken(&tok); err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Failed to create token", err.Error())
			return
		}
		s.jsonResponse(w, http.StatusCreated, tok)
	})

	mux.HandleFunc("/api/v1/gateways/enroll", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			s.jsonError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST required")
			return
		}
		var req struct {
			Token        string `json:"token"`
			GatewayName  string `json:"gateway_name"`
			KeystoreType string `json:"keystore_type"`
			Version      string `json:"version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.jsonError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
			return
		}

		tok, err := s.storage.ConsumeEnrollmentToken(req.Token)
		if err != nil {
			s.jsonError(w, http.StatusUnauthorized, "Invalid Token", err.Error())
			return
		}

		gw := &models.Gateway{
			TenantID:      tok.TenantID,
			EnvironmentID: tok.EnvironmentID,
			Name:          req.GatewayName,
			Status:        "online",
			Version:       req.Version,
			KeystoreType:  req.KeystoreType,
			PolicyGrace:   "72h",
		}
		if gw.Name == "" {
			gw.Name = "gw-" + uuid.New().String()[:6]
		}
		if gw.Version == "" {
			gw.Version = "1.0.0"
		}
		if err := s.storage.CreateGateway(gw); err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Failed to save gateway", err.Error())
			return
		}

		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"gateway":        gw,
			"client_cert":    "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
			"ca_bundle":      "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
			"policy_grace":   gw.PolicyGrace,
			"control_plane":  "/api/v1",
		})
	})

	// Certificate Requests
	mux.HandleFunc("/api/v1/certificate-requests", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		if r.Method == http.MethodGet {
			list, err := s.storage.ListCertificateRequests(tenantID)
			if err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusOK, list)
			return
		}
		if r.Method == http.MethodPost {
			var req models.CertificateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				s.jsonError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
				return
			}
			req.TenantID = tenantID
			if err := s.storage.CreateCertificateRequest(&req); err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}

			// Attempt automatic processing
			cert, err := s.workflow.ProcessRequest(req.ID, tenantID)
			if err != nil {
				// May require approval or be rejected
				updated, _ := s.storage.GetCertificateRequest(tenantID, req.ID)
				s.jsonResponse(w, http.StatusAccepted, map[string]interface{}{
					"request": updated,
					"message": err.Error(),
				})
				return
			}

			s.jsonResponse(w, http.StatusCreated, map[string]interface{}{
				"request":     req,
				"certificate": cert,
			})
			return
		}
	})

	// Approvals
	mux.HandleFunc("/api/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		if r.Method != http.MethodPost {
			s.jsonError(w, http.StatusMethodNotAllowed, "Method Not Allowed", "POST required")
			return
		}
		var app models.Approval
		if err := json.NewDecoder(r.Body).Decode(&app); err != nil {
			s.jsonError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
			return
		}
		app.TenantID = tenantID

		req, err := s.storage.GetCertificateRequest(tenantID, app.RequestID)
		if err != nil {
			s.jsonError(w, http.StatusNotFound, "Request Not Found", err.Error())
			return
		}

		// Enforce Segregation of Duties
		ok, msg := s.policyEngine.EvaluateApproval(&app, req)
		if !ok {
			s.jsonError(w, http.StatusForbidden, "Policy Violation", msg)
			return
		}

		if err := s.storage.CreateApproval(&app); err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
			return
		}

		// Trigger issuance workflow now that approval is recorded
		cert, err := s.workflow.ProcessRequest(req.ID, tenantID)
		if err != nil {
			s.jsonResponse(w, http.StatusOK, map[string]interface{}{
				"approval": app,
				"message":  err.Error(),
			})
			return
		}

		s.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"approval":    app,
			"certificate": cert,
		})
	})

	// Certificates
	mux.HandleFunc("/api/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		certs, err := s.storage.ListCertificates(tenantID)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
			return
		}
		s.jsonResponse(w, http.StatusOK, certs)
	})

	mux.HandleFunc("/api/v1/certificates/", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 4 {
			s.jsonError(w, http.StatusBadRequest, "Invalid Path", "Certificate ID required")
			return
		}
		certID := parts[3]

		if len(parts) == 4 && r.Method == http.MethodGet {
			cert, err := s.storage.GetCertificate(tenantID, certID)
			if err != nil {
				s.jsonError(w, http.StatusNotFound, "Not Found", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusOK, cert)
			return
		}

		// Action endpoints: /api/v1/certificates/:id/revoke
		if len(parts) == 5 && parts[4] == "revoke" && r.Method == http.MethodPost {
			var body struct {
				Reason string `json:"reason"`
				Actor  string `json:"actor"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Reason == "" {
				body.Reason = "cessationOfOperation"
			}
			if body.Actor == "" {
				body.Actor = "admin"
			}
			if err := s.workflow.RevokeCertificate(tenantID, certID, body.Reason, body.Actor); err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Revocation Failed", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusOK, map[string]string{"status": "Revoked", "id": certID})
			return
		}

		// Action endpoints: /api/v1/certificates/:id/deploy
		if len(parts) == 5 && parts[4] == "deploy" && r.Method == http.MethodPost {
			var body struct {
				TargetID string `json:"target_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			result, err := s.workflow.DeployAndVerify(tenantID, certID, body.TargetID)
			if err != nil {
				s.jsonResponse(w, http.StatusUnprocessableEntity, map[string]interface{}{
					"error":  err.Error(),
					"result": result,
				})
				return
			}
			s.jsonResponse(w, http.StatusOK, result)
			return
		}
	})

	// Deployment Targets
	mux.HandleFunc("/api/v1/deployment-targets", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		if r.Method == http.MethodGet {
			list, err := s.storage.ListDeploymentTargets(tenantID)
			if err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusOK, list)
			return
		}
		if r.Method == http.MethodPost {
			var tgt models.DeploymentTarget
			if err := json.NewDecoder(r.Body).Decode(&tgt); err != nil {
				s.jsonError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
				return
			}
			tgt.TenantID = tenantID
			if err := s.storage.CreateDeploymentTarget(&tgt); err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusCreated, tgt)
			return
		}
	})

	// Profiles
	mux.HandleFunc("/api/v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		if r.Method == http.MethodGet {
			list, err := s.storage.ListProfiles(tenantID)
			if err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusOK, list)
			return
		}
		if r.Method == http.MethodPost {
			var p models.CertificateProfile
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				s.jsonError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
				return
			}
			p.TenantID = tenantID
			if err := s.storage.CreateProfile(&p); err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusCreated, p)
			return
		}
	})

	// Discovery & Findings
	mux.HandleFunc("/api/v1/discovery/scans", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		if r.Method == http.MethodGet {
			scans, err := s.storage.ListDiscoveryScans(tenantID)
			if err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusOK, scans)
			return
		}
		if r.Method == http.MethodPost {
			var sc models.DiscoveryScan
			if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
				s.jsonError(w, http.StatusBadRequest, "Invalid JSON", err.Error())
				return
			}
			sc.TenantID = tenantID
			sc.Status = "completed"
			sc.TargetsScanned = len(sc.CIDRs) * len(sc.Ports)
			if sc.TargetsScanned == 0 {
				sc.TargetsScanned = 1
			}
			if err := s.storage.CreateDiscoveryScan(&sc); err != nil {
				s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
				return
			}
			s.jsonResponse(w, http.StatusCreated, sc)
			return
		}
	})

	mux.HandleFunc("/api/v1/discovery/findings", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		scanID := r.URL.Query().Get("scan_id")
		findings, err := s.storage.ListDiscoveryFindings(tenantID, scanID)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
			return
		}
		s.jsonResponse(w, http.StatusOK, findings)
	})

	// Audit Ledger & Verification
	mux.HandleFunc("/api/v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		events, err := s.storage.ListAuditEvents(tenantID, 100)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
			return
		}
		s.jsonResponse(w, http.StatusOK, events)
	})

	mux.HandleFunc("/api/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		events, err := s.storage.ListAuditEvents(tenantID, 1000)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
			return
		}
		sth, _ := s.storage.GetLatestTreeHead(tenantID)
		res := audit.VerifyLedger(tenantID, events, sth)
		s.jsonResponse(w, http.StatusOK, res)
	})

	// CBOM & Reports
	mux.HandleFunc("/api/v1/reports/cbom", func(w http.ResponseWriter, r *http.Request) {
		tenantID := s.getTenantID(r)
		certs, err := s.storage.ListCertificates(tenantID)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, "Storage Error", err.Error())
			return
		}
		cbom, err := inventory.GenerateCBOM(tenantID, certs)
		if err != nil {
			s.jsonError(w, http.StatusInternalServerError, "CBOM Error", err.Error())
			return
		}
		s.jsonResponse(w, http.StatusOK, cbom)
	})

	// Web UI Frontend static files
	mux.Handle("/", http.FileServer(http.Dir("./web")))
}
