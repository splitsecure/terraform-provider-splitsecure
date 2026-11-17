// Package vaultapi wraps the vault API calls the provider resources share:
// following approval tickets, reading records and mapping HCL enums to protos.
package vaultapi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"connectrpc.com/connect"

	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1/vaultusev1connect"
)

// Terminal ticket statuses, wrapped by the errors AwaitCreate and AwaitDelete return.
var (
	ErrDenied         = errors.New("request denied")
	ErrExpired        = errors.New("request expired before it was approved")
	ErrCancelled      = errors.New("request cancelled")
	ErrReleaseExpired = errors.New("request release window expired: the record was created but its id can no longer be collected")
)

var (
	errNoResult         = errors.New("server returned neither a result nor a ticket")
	errUnexpectedResult = errors.New("ticket resolved to an unexpected outcome")
	errUnknownStatus    = errors.New("ticket ended in an unknown status")
)

// emptyPollPause spaces polls that come back with no outcome, so an
// immediately-returning server is not hammered.
const emptyPollPause = time.Second

// Transient poll errors retry with a doubling pause between these bounds.
const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

const (
	cancelTimeout = 10 * time.Second
	cancelReason  = "cancelled by the Terraform provider"
)

// AwaitCreate returns the result of a create, polling its ticket when the server did not answer inline.
// When err is non-nil and the result is non-nil, the record exists: record its id so Terraform taints it.
func AwaitCreate(ctx context.Context, c vaultusev1connect.VaultUseServiceClient, vaultID string, outcome *vaultusev1.CreateOutcome) (*vaultusev1.CreateResult, error) {
	if result := outcome.GetResult(); result != nil {
		return result, nil
	}

	ticket := outcome.GetTicket()
	if ticket == nil {
		return nil, errNoResult
	}

	resolved, err := pollUntilResolved(ctx, c, vaultID, ticket.GetTicketId())
	result := resolved.GetCreateResult()
	if err != nil {
		return result, err
	}

	if result == nil {
		return nil, fmt.Errorf("%w: %T", errUnexpectedResult, resolved.GetOutcome())
	}

	return result, nil
}

// AwaitDelete returns once a delete has completed, polling its ticket when the server did not answer inline.
func AwaitDelete(ctx context.Context, c vaultusev1connect.VaultUseServiceClient, vaultID string, outcome *vaultusev1.DeleteOutcome) error {
	if outcome.GetResult() != nil {
		return nil
	}

	ticket := outcome.GetTicket()
	if ticket == nil {
		return errNoResult
	}

	resolved, err := pollUntilResolved(ctx, c, vaultID, ticket.GetTicketId())
	if err != nil {
		return err
	}

	if resolved.GetDeleteResult() == nil {
		return fmt.Errorf("%w: %T", errUnexpectedResult, resolved.GetOutcome())
	}

	return nil
}

// AwaitRelease returns the result of a use request, polling its ticket when the server did not answer inline.
func AwaitRelease(ctx context.Context, c vaultusev1connect.VaultUseServiceClient, vaultID string, outcome *vaultusev1.ReleaseOutcome) (*vaultusev1.ReleaseResult, error) {
	if result := outcome.GetResult(); result != nil {
		return result, nil
	}

	ticket := outcome.GetTicket()
	if ticket == nil {
		return nil, errNoResult
	}

	resolved, err := pollUntilResolved(ctx, c, vaultID, ticket.GetTicketId())
	if err != nil {
		return nil, err
	}

	result := resolved.GetReleaseResult()
	if result == nil {
		return nil, fmt.Errorf("%w: %T", errUnexpectedResult, resolved.GetOutcome())
	}

	return result, nil
}

// verdictError marks a terminal ticket status, which needs no cancel.
type verdictError struct{ err error }

func (e *verdictError) Error() string { return e.err.Error() }

func (e *verdictError) Unwrap() error { return e.err }

// pollUntilResolved polls a ticket and cancels it on any exit that is not a verdict, so no approver acts on a request nobody awaits.
// When the cancel is refused, the ticket may already be released: the outcome of one last poll comes back with the error.
func pollUntilResolved(ctx context.Context, c vaultusev1connect.VaultUseServiceClient, vaultID string, ticketID []byte) (*vaultusev1.TicketOutcome, error) {
	outcome, err := poll(ctx, c, vaultID, ticketID)
	if err == nil {
		return outcome, nil
	}

	var verdict *verdictError
	if errors.As(err, &verdict) {
		return nil, verdict.err
	}

	cancelErr := cancelTicket(ctx, c, vaultID, ticketID)
	if cancelErr == nil {
		return nil, err
	}

	return pollOnce(ctx, c, vaultID, ticketID), fmt.Errorf("%w; %w", err, cancelErr)
}

func cancelTicket(ctx context.Context, c vaultusev1connect.VaultUseServiceClient, vaultID string, ticketID []byte) error {
	ctx, stop := context.WithTimeout(context.WithoutCancel(ctx), cancelTimeout)
	defer stop()

	_, err := c.Cancel(ctx, connect.NewRequest(&vaultusev1.CancelRequest{
		Base: &vaultusev1.CancelRequest_Base{
			VaultId:  vaultID,
			TicketId: ticketID,
			Reason:   cancelReason,
		},
	}))
	if err != nil {
		return fmt.Errorf("cancelling ticket: %w", err)
	}

	return nil
}

// pollOnce asks for the ticket outcome without blocking and returns nil when there is none.
func pollOnce(ctx context.Context, c vaultusev1connect.VaultUseServiceClient, vaultID string, ticketID []byte) *vaultusev1.TicketOutcome {
	ctx, stop := context.WithTimeout(context.WithoutCancel(ctx), cancelTimeout)
	defer stop()

	resp, err := c.PollTicket(ctx, connect.NewRequest(&vaultusev1.PollTicketRequest{
		Base:    &vaultusev1.PollTicketRequest_Base{VaultId: vaultID, TicketId: ticketID},
		NoBlock: true,
	}))
	if err != nil {
		return nil
	}

	return resp.Msg.GetOutcome()
}

func isTransient(err error) bool {
	transient := []connect.Code{connect.CodeUnavailable, connect.CodeResourceExhausted, connect.CodeAborted, connect.CodeDeadlineExceeded}

	return slices.Contains(transient, connect.CodeOf(err))
}

func sleep(ctx context.Context, pause time.Duration) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("waiting for approval: %w", ctx.Err())
	case <-time.After(pause):
		return nil
	}
}

// verdictOf returns the outcome or the verdict error when the poll response ends the wait, and neither while the ticket is pending.
func verdictOf(outcome *vaultusev1.TicketOutcome) (*vaultusev1.TicketOutcome, error) {
	if status := outcome.GetStatus(); status != nil {
		return nil, &verdictError{err: statusError(status)}
	}

	if outcome.GetOutcome() != nil {
		return outcome, nil
	}

	if len(outcome.ProtoReflect().GetUnknown()) > 0 {
		return nil, &verdictError{err: errUnknownStatus}
	}

	return nil, nil //nolint:nilnil // neither an outcome nor a verdict: the ticket is pending.
}

func poll(ctx context.Context, c vaultusev1connect.VaultUseServiceClient, vaultID string, ticketID []byte) (*vaultusev1.TicketOutcome, error) {
	backoff := minBackoff

	for {
		resp, err := c.PollTicket(ctx, connect.NewRequest(&vaultusev1.PollTicketRequest{
			Base: &vaultusev1.PollTicketRequest_Base{
				VaultId:  vaultID,
				TicketId: ticketID,
			},
		}))

		pause := emptyPollPause

		switch {
		case err != nil && (ctx.Err() != nil || !isTransient(err)):
			return nil, fmt.Errorf("polling ticket: %w", err)
		case err != nil:
			pause = backoff
			backoff = min(backoff*2, maxBackoff)
		default:
			backoff = minBackoff

			outcome, verdict := verdictOf(resp.Msg.GetOutcome())
			if outcome != nil || verdict != nil {
				return outcome, verdict
			}
		}

		err = sleep(ctx, pause)
		if err != nil {
			return nil, err
		}
	}
}

func statusError(status *vaultusev1.TicketStatus) error {
	switch {
	case status.GetDenied() != nil:
		if reason := status.GetDenied().GetReason(); reason != "" {
			return fmt.Errorf("%w: %s", ErrDenied, reason)
		}

		return ErrDenied
	case status.GetExpired() != nil:
		return ErrExpired
	case status.GetCancelled() != nil:
		return ErrCancelled
	case status.GetReleaseExpired() != nil:
		return ErrReleaseExpired
	default:
		return errUnknownStatus
	}
}
