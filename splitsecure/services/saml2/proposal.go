package saml2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	conveniencestorev1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/conveniencestore/v1"
	enclavev1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/enclave/v1"
	enclaveroundtripv1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/enclaveroundtrip/v1"
	proposalsv1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/proposals/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

// proposalTimeout is the default wall-clock limit for waiting on a
// proposal to be approved and executed. Voter response is human-scale,
// so the default is generous; callers can override per-resource.
const proposalTimeout = 30 * time.Minute

// destroyJustification renders the per-Delete justification voters
// see on a `terraform destroy` proposal. The HCL `justification`
// attribute is write-only on Create -- never persisted to state --
// so we can't replay the user's create-time text here. Stamp the
// resource kind, friendly name, and resource_s2r so audit logs and
// the voter approval UI can identify what's being removed.
func destroyJustification(kind, name, resourceS2R string) string {
	return "Removing " + kind + " " + name + " (" + resourceS2R + ") via terraform destroy."
}

// pollInterval is the default sleep between unary polls (request ->
// proposal_id, proposal status, resource lookup). Conservative so a
// long `tf apply` doesn't hammer the API.
const pollInterval = 5 * time.Second

// errOrgS2RRequired is returned by send helpers when the caller
// forgot to pass org_s2r. A sentinel keeps err113 happy and lets
// callers distinguish the validation miss from transport failures.
var errOrgS2RRequired = errors.New("org_s2r is required")

// errProposalRejected wraps a server-rendered rejection message from
// the proposal's terminal status. The message is concatenated with
// %w in callers so consumers can errors.Is it back.
var errProposalRejected = errors.New("proposal rejected")

// sendAndAwaitResource drives the full server-side proposal flow for a
// Create: submits the caller-built invoke_request to a fresh
// proposal-scoped managed enclave, waits for the enclave reply to
// surface the proposal id, polls the proposal to Completed, then
// resolves the proposal to the resource_s2r of the minted record.
//
// The three polling loops are all unary: Send returns a request_id,
// GetProposalForRequest returns a proposal_id once the enclave has
// replied, GetProposal reports the lifecycle status, and
// GetProposalResource returns the resource_s2r after execution writes
// the canonical record + proposal->resource index atomically.
func sendAndAwaitResource(
	ctx context.Context,
	c *client.Client,
	orgS2R string,
	invokeReq *enclavev1.InvokeRequest,
	timeout time.Duration,
) (string, error) {
	if orgS2R == "" {
		return "", errOrgS2RRequired
	}
	if timeout <= 0 {
		timeout = proposalTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	requestID, err := send(ctx, c, orgS2R, invokeReq)
	if err != nil {
		return "", err
	}
	tflog.Debug(ctx, "proposal send returned", map[string]any{
		"request_id": requestID,
	})

	proposalID, err := awaitProposalID(ctx, c, requestID)
	if err != nil {
		return "", err
	}
	tflog.Debug(ctx, "proposal minted", map[string]any{
		"proposal_id": proposalID,
	})

	err = awaitProposalTerminal(ctx, c, proposalID)
	if err != nil {
		return "", err
	}

	return awaitProposalResource(ctx, c, proposalID)
}

// sendAndAwaitDelete drives the Delete path. Same Send/track shape as
// Create but without the final resource resolution: the deleted
// record's s2r is the one the caller already has in state, and its
// record has become a tombstone (readable via GetSAML2Resources but
// not via GetProposalResource since tombstones aren't indexed).
func sendAndAwaitDelete(
	ctx context.Context,
	c *client.Client,
	orgS2R string,
	invokeReq *enclavev1.InvokeRequest,
	timeout time.Duration,
) error {
	if orgS2R == "" {
		return errOrgS2RRequired
	}
	if timeout <= 0 {
		timeout = proposalTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	requestID, err := send(ctx, c, orgS2R, invokeReq)
	if err != nil {
		return err
	}
	proposalID, err := awaitProposalID(ctx, c, requestID)
	if err != nil {
		return err
	}

	return awaitProposalTerminal(ctx, c, proposalID)
}

// send invokes EnclaveRoundtripService.Send targeting a fresh managed
// enclave in the named org, returning the request id the enclave's
// reply is keyed against.
func send(ctx context.Context, c *client.Client, orgS2R string, invokeReq *enclavev1.InvokeRequest) ([]byte, error) {
	resp, err := c.EnclaveRoundtripService.Send(ctx, connect.NewRequest(&enclaveroundtripv1.SendRequest{
		Base: &enclaveroundtripv1.SendRequest_Base{
			Target: &enclaveroundtripv1.SendRequest_Base_NewProposalScopedEnclave{
				NewProposalScopedEnclave: orgS2R,
			},
			InvokeRequest: invokeReq,
		},
	}))
	if err != nil {
		return nil, fmt.Errorf("Send: %w", err)
	}

	return resp.Msg.GetRequestId(), nil
}

// awaitProposalID polls GetProposalForRequest until the enclave's
// reply surfaces a proposal id. Returns ctx.Err() on timeout.
func awaitProposalID(ctx context.Context, c *client.Client, requestID []byte) ([]byte, error) {
	for {
		resp, err := c.EnclaveRoundtripService.GetProposalForRequest(ctx, connect.NewRequest(&enclaveroundtripv1.GetProposalForRequestRequest{
			RequestId: requestID,
		}))
		if err != nil {
			return nil, fmt.Errorf("GetProposalForRequest: %w", err)
		}
		if pid := resp.Msg.GetProposalId(); len(pid) > 0 {
			return pid, nil
		}

		err = sleep(ctx, pollInterval)
		if err != nil {
			return nil, err
		}
	}
}

// awaitProposalTerminal polls GetProposal until the proposal reaches
// Completed or Error. Returns the error message when the proposal
// fails, so callers can surface it to terraform.
func awaitProposalTerminal(ctx context.Context, c *client.Client, proposalID []byte) error {
	for {
		resp, err := c.ProposalsService.GetProposal(ctx, connect.NewRequest(&proposalsv1.GetProposalRequest{
			Base: &proposalsv1.GetProposalRequest_Base{
				ProposalId: proposalID,
			},
		}))
		if err != nil {
			return fmt.Errorf("GetProposal: %w", err)
		}
		switch status := resp.Msg.GetMetadata().GetStatus().GetStatus().(type) {
		case *proposalsv1.ProposalStatus_Completed_:
			return nil
		case *proposalsv1.ProposalStatus_Error_:
			return fmt.Errorf("%w: %s", errProposalRejected, status.Error.GetMessage())
		case *proposalsv1.ProposalStatus_InProgress_, nil:
			// Keep polling.
		}

		err = sleep(ctx, pollInterval)
		if err != nil {
			return err
		}
	}
}

// awaitProposalResource polls GetProposalResource until the
// proposal's resource index is populated, which happens atomically
// with the canonical record write at proposal-execute time. Empty
// responses are expected during the replication window between
// proposal Completed and resource Store.
func awaitProposalResource(ctx context.Context, c *client.Client, proposalID []byte) (string, error) {
	for {
		resp, err := c.ConvenienceStoreService.GetProposalResource(ctx, connect.NewRequest(&conveniencestorev1.GetProposalResourceRequest{
			Base: &conveniencestorev1.GetProposalResourceRequest_Base{
				ProposalId: proposalID,
			},
		}))
		if err != nil {
			return "", fmt.Errorf("GetProposalResource: %w", err)
		}
		if s := resp.Msg.GetResourceS2R(); s != "" {
			return s, nil
		}

		err = sleep(ctx, pollInterval)
		if err != nil {
			return "", err
		}
	}
}

// fetchSAML2Record reads a single SAML2 record by its s2r URI via the
// batch getter. Returns nil when the record isn't found (tombstoned,
// never created, or caller lost access).
func fetchSAML2Record(ctx context.Context, c *client.Client, resourceS2R string) (*conveniencestorev1.SAML2ResourceRecord, error) {
	resp, err := c.ConvenienceStoreService.GetSAML2Resources(ctx, connect.NewRequest(&conveniencestorev1.GetSAML2ResourcesRequest{
		Base: &conveniencestorev1.GetSAML2ResourcesRequest_Base{
			ResourceS2Rs: []string{resourceS2R},
		},
	}))
	if err != nil {
		return nil, fmt.Errorf("GetSAML2Resources: %w", err)
	}

	return resp.Msg.GetResources()[resourceS2R], nil
}

// sleep is a context-aware sleep that returns early on cancel/timeout.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
