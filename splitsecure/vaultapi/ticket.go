// Package vaultapi wraps the vault API calls the provider resources share:
// following approval tickets, reading records and mapping HCL enums to protos.
package vaultapi

import (
	"context"
	"errors"
	"fmt"
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
	ErrReleaseExpired = errors.New("request release window expired")
)

var (
	errNoResult         = errors.New("server returned neither a result nor a ticket")
	errUnexpectedResult = errors.New("ticket resolved to an unexpected outcome")
	errUnknownStatus    = errors.New("ticket ended in an unknown status")
)

// emptyPollPause spaces polls that come back with no outcome, so an
// immediately-returning server is not hammered.
const emptyPollPause = time.Second

// AwaitCreate returns the result of a create, polling its ticket when the server did not answer inline.
func AwaitCreate(ctx context.Context, c vaultusev1connect.VaultUseServiceClient, vaultID string, outcome *vaultusev1.CreateOutcome) (*vaultusev1.CreateResult, error) {
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

	result := resolved.GetCreateResult()
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

func pollUntilResolved(ctx context.Context, c vaultusev1connect.VaultUseServiceClient, vaultID string, ticketID []byte) (*vaultusev1.TicketOutcome, error) {
	for {
		resp, err := c.PollTicket(ctx, connect.NewRequest(&vaultusev1.PollTicketRequest{
			Base: &vaultusev1.PollTicketRequest_Base{
				VaultId:  vaultID,
				TicketId: ticketID,
			},
		}))
		if err != nil {
			// A long poll cut by a transport deadline is not a verdict; the caller's own deadline still ends the loop.
			if connect.CodeOf(err) == connect.CodeDeadlineExceeded && ctx.Err() == nil {
				continue
			}

			return nil, fmt.Errorf("polling ticket: %w", err)
		}

		outcome := resp.Msg.GetOutcome()
		if status := outcome.GetStatus(); status != nil {
			return nil, statusError(status)
		}

		if outcome.GetOutcome() != nil {
			return outcome, nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for approval: %w", ctx.Err())
		case <-time.After(emptyPollPause):
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
