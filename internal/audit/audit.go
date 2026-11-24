package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"clm/internal/models"
)

type AuditVerificationResult struct {
	TenantID            string   `json:"tenant_id"`
	EventsChecked       int      `json:"events_checked"`
	HashChainValid      bool     `json:"hash_chain_valid"`
	SignedTreeHeadsValid bool    `json:"signed_tree_heads_valid"`
	GapsDetected        int      `json:"gaps_detected"`
	TamperedEvents      []string `json:"tampered_events,omitempty"`
	RootHash            string   `json:"root_hash"`
	VerifiedAt          string   `json:"verified_at"`
}

// ComputeEventHash computes the SHA-256 hash of an audit event.
func ComputeEventHash(prevHash string, seq int64, actor, action, targetType, targetID, policyDecision string, ts time.Time) string {
	input := fmt.Sprintf("%s:%d:%s:%s:%s:%s:%s:%s",
		prevHash, seq, actor, action, targetType, targetID, policyDecision, ts.UTC().Format(time.RFC3339Nano))
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// BuildMerkleRoot calculates the Merkle tree root hash for a slice of event hashes (RFC 6962).
func BuildMerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		empty := sha256.Sum256([]byte(""))
		return hex.EncodeToString(empty[:])
	}
	if len(hashes) == 1 {
		return hashes[0]
	}

	var nextLevel []string
	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			combined := hashes[i] + hashes[i+1]
			h := sha256.Sum256([]byte(combined))
			nextLevel = append(nextLevel, hex.EncodeToString(h[:]))
		} else {
			// Odd number: promote single hash
			nextLevel = append(nextLevel, hashes[i])
		}
	}
	return BuildMerkleRoot(nextLevel)
}

// VerifyLedger runs an independent integrity verification over tenant audit events (README Sec 26).
func VerifyLedger(tenantID string, events []*models.AuditEvent, latestSTH *models.AuditTreeHead) *AuditVerificationResult {
	res := &AuditVerificationResult{
		TenantID:             tenantID,
		EventsChecked:        len(events),
		HashChainValid:       true,
		SignedTreeHeadsValid: true,
		VerifiedAt:           time.Now().UTC().Format(time.RFC3339),
	}

	if len(events) == 0 {
		return res
	}

	var hashes []string
	expectedPrev := "0000000000000000000000000000000000000000000000000000000000000000"

	for i, ev := range events {
		expectedSeq := int64(i + 1)
		if ev.Sequence != expectedSeq {
			res.GapsDetected++
			res.HashChainValid = false
			res.TamperedEvents = append(res.TamperedEvents, fmt.Sprintf("Event %s has sequence %d (expected %d)", ev.ID, ev.Sequence, expectedSeq))
		}

		if i > 0 && ev.PrevHash != expectedPrev {
			res.HashChainValid = false
			res.TamperedEvents = append(res.TamperedEvents, fmt.Sprintf("Event %s prev_hash mismatch: got %s, want %s", ev.ID, ev.PrevHash, expectedPrev))
		}

		expectedPrev = ev.Hash
		hashes = append(hashes, ev.Hash)
	}

	merkleRoot := BuildMerkleRoot(hashes)
	res.RootHash = merkleRoot

	if latestSTH != nil {
		if latestSTH.RootHash != merkleRoot {
			res.SignedTreeHeadsValid = false
			res.TamperedEvents = append(res.TamperedEvents, fmt.Sprintf("Signed Tree Head root_hash mismatch: STH has %s, calculated %s", latestSTH.RootHash, merkleRoot))
		}
	}

	return res
}
