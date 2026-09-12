package sdk

import (
	"testing"
	"time"

	"github.com/0xkey-io/sdk-go/pkg/api/models"
)

func TestMFARequestBuilders(t *testing.T) {
	status := newGetMFAStatusRequest("org-id", "activity-id", "user-id")
	if *status.OrganizationID != "org-id" || *status.ActivityID != "activity-id" || status.UserID != "user-id" {
		t.Fatalf("unexpected status request: %+v", status)
	}

	approvedAt := time.UnixMilli(1_725_000_000_123)
	approve := newApproveActivityRequest("org-id", "fingerprint", approvedAt)
	if *approve.Type != models.ApproveActivityRequestTypeACTIVITYTYPEAPPROVEACTIVITY {
		t.Fatalf("unexpected type: %s", *approve.Type)
	}
	if *approve.TimestampMs != "1725000000123" || *approve.Parameters.Fingerprint != "fingerprint" {
		t.Fatalf("unexpected approve request: %+v", approve)
	}
}

func TestMFAClientMethodsAreExplicit(t *testing.T) {
	get := (*Client).GetMFAStatus
	approve := (*Client).ApproveActivity
	_ = get
	_ = approve
}
