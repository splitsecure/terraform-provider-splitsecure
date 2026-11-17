// Command sign-release asks a SplitSecure OpenPGP key for a detached
// signature over a file, from a GitHub Actions job signed in through
// workload identity. A quorum approves each request.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	openpgpv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/openpgp/v1"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1/vaultusev1connect"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/authn"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
)

const (
	// approvalWindow is how long approvers have before the request expires.
	approvalWindow = 5 * time.Minute
	runTimeout     = 6 * time.Minute

	sigTypeBinary = 0x00
)

var (
	errMissingFlag = errors.New("missing required flag")
	errNoSignature = errors.New("the released result carries no signature")
)

type options struct {
	endpoint       string
	serviceAccount string
	vaultID        string
	keyID          string
	in             string
	out            string
	justification  string
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign-release:", err)
		os.Exit(1)
	}
}

func run() error {
	opts, err := parseFlags()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()

	signature, err := sign(ctx, opts)
	if err != nil {
		return err
	}

	err = os.WriteFile(opts.out, signature, 0o600)
	if err != nil {
		return fmt.Errorf("writing %s: %w", opts.out, err)
	}

	return nil
}

func parseFlags() (options, error) {
	var opts options

	flag.StringVar(&opts.endpoint, "endpoint", "", "SplitSecure API origin")
	flag.StringVar(&opts.serviceAccount, "service-account", "", "service account s2r")
	flag.StringVar(&opts.vaultID, "vault", "", "vault id")
	flag.StringVar(&opts.keyID, "key", "", "openpgp-key record id")
	flag.StringVar(&opts.in, "in", "", "file to sign")
	flag.StringVar(&opts.out, "out", "", "where to write the binary signature")
	flag.StringVar(&opts.justification, "justification", "", "reason shown to approvers")
	flag.Parse()

	required := map[string]string{
		"endpoint":        opts.endpoint,
		"service-account": opts.serviceAccount,
		"vault":           opts.vaultID,
		"key":             opts.keyID,
		"in":              opts.in,
		"out":             opts.out,
	}
	for name, value := range required {
		if value == "" {
			return options{}, fmt.Errorf("%w: -%s", errMissingFlag, name)
		}
	}

	return opts, nil
}

func sign(ctx context.Context, opts options) ([]byte, error) {
	document, err := os.ReadFile(opts.in)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", opts.in, err)
	}

	tokens, err := authn.GitHubActionsTokenSource(nil)
	if err != nil {
		return nil, fmt.Errorf("getting the GitHub token source: %w", err)
	}

	transport, err := authn.NewTransport(authn.Config{
		Endpoint: opts.endpoint,
		Workload: &authn.Workload{ServiceAccountS2R: opts.serviceAccount, TokenSource: tokens},
	})
	if err != nil {
		return nil, fmt.Errorf("building the transport: %w", err)
	}

	client := vaultusev1connect.NewVaultUseServiceClient(&http.Client{Transport: transport}, opts.endpoint)

	resp, err := client.SignOpenPGP(ctx, connect.NewRequest(&vaultusev1.SignOpenPGPRequest{
		Base: &vaultusev1.SignOpenPGPRequest_Base{
			VaultId:  opts.vaultID,
			KeyId:    opts.keyID,
			Document: document,
			SigType:  sigTypeBinary,
			Options: &vaultusev1.UseOptions{
				Justification: opts.justification,
				MaxPending:    durationpb.New(approvalWindow),
			},
		},
	}))
	if err != nil {
		return nil, fmt.Errorf("submitting the signature request: %w", err)
	}

	result, err := vaultapi.AwaitRelease(ctx, client, opts.vaultID, resp.Msg.GetOutcome())
	if err != nil {
		return nil, fmt.Errorf("waiting for approval: %w", err)
	}

	return signaturePacket(result.GetClearValue())
}

// signaturePacket decodes the SignResult a released sign request carries and returns its signature packet.
func signaturePacket(clearValue []byte) ([]byte, error) {
	var result openpgpv1.SignResult

	err := proto.Unmarshal(clearValue, &result)
	if err != nil {
		return nil, fmt.Errorf("decoding the sign result: %w", err)
	}

	packet := result.GetSignaturePacket()
	if len(packet) == 0 {
		return nil, errNoSignature
	}

	return packet, nil
}
