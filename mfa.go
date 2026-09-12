package sdk

import (
	"context"
	"strconv"
	"time"

	"github.com/0xkey-io/sdk-go/pkg/api/client/consensus"
	mfapolicies "github.com/0xkey-io/sdk-go/pkg/api/client/m_f_a_policies"
	"github.com/0xkey-io/sdk-go/pkg/api/models"
)

// GetMFAStatus explicitly queries whether an MFA-paused activity has satisfied
// all required methods. It never approves or resumes the activity implicitly.
func (c *Client) GetMFAStatus(ctx context.Context, organizationID, activityID, userID string) (*models.GetMfaStatusResponse, error) {
	response, err := c.Client.MfaPolicies.GetMfaStatus(
		mfapolicies.NewGetMfaStatusParamsWithContext(ctx).WithBody(newGetMFAStatusRequest(organizationID, activityID, userID)),
		c.Authenticator,
	)
	if err != nil {
		return nil, err
	}
	return response.Payload, nil
}

// ApproveActivity explicitly submits approval after the caller has inspected
// MFA status. Keeping this separate prevents an SDK poller from auto-approving.
func (c *Client) ApproveActivity(ctx context.Context, organizationID, fingerprint string, timestamp time.Time) (*models.ActivityResponse, error) {
	response, err := c.Client.Consensus.ApproveActivity(
		consensus.NewApproveActivityParamsWithContext(ctx).WithBody(newApproveActivityRequest(organizationID, fingerprint, timestamp)),
		c.Authenticator,
	)
	if err != nil {
		return nil, err
	}
	return response.Payload, nil
}

func newGetMFAStatusRequest(organizationID, activityID, userID string) *models.GetMfaStatusRequest {
	return &models.GetMfaStatusRequest{OrganizationID: &organizationID, ActivityID: &activityID, UserID: userID}
}

func newApproveActivityRequest(organizationID, fingerprint string, timestamp time.Time) *models.ApproveActivityRequest {
	requestType := models.ApproveActivityRequestTypeACTIVITYTYPEAPPROVEACTIVITY
	timestampMs := strconv.FormatInt(timestamp.UnixMilli(), 10)
	return &models.ApproveActivityRequest{
		OrganizationID: &organizationID,
		Parameters:     &models.ApproveActivityIntent{Fingerprint: &fingerprint},
		TimestampMs:    &timestampMs,
		Type:           &requestType,
	}
}
