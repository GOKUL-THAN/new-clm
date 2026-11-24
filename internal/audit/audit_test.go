package audit

import (
	"testing"
	"time"

	"clm/internal/models"
)

func TestAuditLedgerVerification(t *testing.T) {
	tenantID := "tenant_acme"
	now := time.Now().UTC()

	var events []*models.AuditEvent
	prevHash := "0000000000000000000000000000000000000000000000000000000000000000"

	actions := []string{"cert.requested", "cert.approved", "cert.issued", "cert.deployed", "cert.verified"}

	for i, action := range actions {
		seq := int64(i + 1)
		ts := now.Add(time.Duration(i) * time.Minute)
		h := ComputeEventHash(prevHash, seq, "alice", action, "certificate", "cert_100", "allow", ts)

		ev := &models.AuditEvent{
			ID:             "ev_" + string(rune('a'+i)),
			TenantID:       tenantID,
			Sequence:       seq,
			Actor:          "alice",
			Action:         action,
			TargetType:     "certificate",
			TargetID:       "cert_100",
			PolicyDecision: "allow",
			PrevHash:       prevHash,
			Hash:           h,
			Timestamp:      ts,
		}
		events = append(events, ev)
		prevHash = h
	}

	// Generate expected STH
	var hashes []string
	for _, ev := range events {
		hashes = append(hashes, ev.Hash)
	}
	root := BuildMerkleRoot(hashes)

	sth := &models.AuditTreeHead{
		TenantID:       tenantID,
		TreeSize:       int64(len(events)),
		RootHash:       root,
		Signature:      "sig_rsa_pss_mock",
		TimestampToken: "rfc3161_token_mock",
	}

	// 1. Verify valid ledger
	resValid := VerifyLedger(tenantID, events, sth)
	if !resValid.HashChainValid {
		t.Errorf("expected hash chain to be valid, got tampered: %v", resValid.TamperedEvents)
	}
	if !resValid.SignedTreeHeadsValid {
		t.Errorf("expected STH to be valid")
	}
	if resValid.GapsDetected != 0 {
		t.Errorf("expected 0 gaps, got %d", resValid.GapsDetected)
	}

	// 2. Test tampering detection (modified event in the chain)
	tamperedEvents := make([]*models.AuditEvent, len(events))
	copy(tamperedEvents, events)
	tamperedEvents[2] = &models.AuditEvent{
		ID:        events[2].ID,
		TenantID:  tenantID,
		Sequence:  events[2].Sequence,
		Actor:     "malicious_actor", // Tampered!
		PrevHash:  events[2].PrevHash,
		Hash:      "forged_hash_123",
		Timestamp: events[2].Timestamp,
	}

	resTampered := VerifyLedger(tenantID, tamperedEvents, sth)
	if resTampered.HashChainValid {
		t.Errorf("expected tampering to be detected in hash chain")
	}
	if resTampered.SignedTreeHeadsValid {
		t.Errorf("expected STH check to fail on tampered ledger")
	}
}
