package connectedapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaulttypesv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaulttypes/v1"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

const appAddress = "splitsecure_connected_app.a"

var errServerWrite = errors.New("the update wrote to the server")

// appProvider serves the connected app resource alone, on a fake vault client.
type appProvider struct{ c *client.Client }

func (p *appProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "splitsecure"
}

func (p *appProvider) Schema(context.Context, provider.SchemaRequest, *provider.SchemaResponse) {}

func (p *appProvider) Configure(_ context.Context, _ provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	resp.ResourceData = p.c
}

func (p *appProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewConnectedAppResource}
}

func (p *appProvider) DataSources(context.Context) []func() datasource.DataSource { return nil }

// vaultServer stores the one app a create sends and counts every write after it.
type vaultServer struct {
	mu     sync.Mutex
	app    *pb.CreateAppParams
	writes int
}

func (s *vaultServer) wrote() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.writes
}

func (s *vaultServer) client(t *testing.T) *client.Client {
	t.Helper()

	use := &vaultfake.Use{
		OnCreateConnectedApp: func(req *vaultusev1.CreateConnectedAppRequest) (*vaultusev1.CreateConnectedAppResponse, error) {
			s.mu.Lock()
			defer s.mu.Unlock()

			s.app, s.writes = req.GetBase().GetApp(), s.writes+1

			return &vaultusev1.CreateConnectedAppResponse{Outcome: vaultfake.CreateOutcome(false, "node-1")}, nil
		},
		OnDelete: func(*vaultusev1.DeleteRequest) (*vaultusev1.DeleteResponse, error) {
			s.mu.Lock()
			defer s.mu.Unlock()

			s.writes++

			return &vaultusev1.DeleteResponse{Outcome: vaultfake.DeleteOutcome(false)}, nil
		},
	}

	browse := &vaultfake.Browse{
		OnListNodes: func(req *vaultbrowsev1.ListNodesRequest) (*vaultbrowsev1.ListNodesResponse, error) {
			if req.GetBase().GetLocator().GetParentNodeId() != "" {
				return &vaultbrowsev1.ListNodesResponse{}, nil
			}

			return &vaultbrowsev1.ListNodesResponse{Children: []*vaulttypesv1.Node{{NodeId: "issuer-1", Record: &vaulttypesv1.RecordFacts{Kind: vaultapi.KindSAML2IDP}}}}, nil
		},
		OnGetRecord: func(req *vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
			if req.GetBase().GetNodeId() == "issuer-1" {
				return vaultfake.Record(t, vaultapi.KindSAML2IDP, &teamresourcev1.BaseResourceAttributes{Name: "idp"}, idpNode("issuer-1", idpSerial).params), nil
			}

			s.mu.Lock()
			defer s.mu.Unlock()

			if s.app == nil || req.GetBase().GetNodeId() != "node-1" {
				return nil, connect.NewError(connect.CodeNotFound, errGone)
			}

			attrs := &teamresourcev1.BaseResourceAttributes{Name: "aws-prod", NotificationPolicy: teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE}

			return vaultfake.Record(t, kindConnectedApp, attrs, recordFromCreate(s.app)), nil
		},
		OnMoveNode: func(*vaultbrowsev1.MoveNodeRequest) (*vaultbrowsev1.MoveNodeResponse, error) {
			s.mu.Lock()
			defer s.mu.Unlock()

			s.writes++

			return &vaultbrowsev1.MoveNodeResponse{}, nil
		},
	}

	return newClient(t, use, browse)
}

// coreTest runs steps through the Terraform binary, which checks every plan the provider makes.
func coreTest(t *testing.T, server *vaultServer, steps ...tfresource.TestStep) {
	t.Helper()

	if os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		_, err := exec.LookPath("terraform")
		if err != nil {
			t.Skip("no terraform binary: set TF_ACC_TERRAFORM_PATH or put terraform on PATH")
		}
	}

	c := server.client(t)

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"splitsecure": providerserver.NewProtocol6WithError(&appProvider{c: c}),
		},
		Steps: steps,
	})
}

const awsAppHead = `
resource "splitsecure_connected_app" "a" {
  issuer_vault_id = "vault-1"
  issuer_id       = "issuer-1"
  template        = "saml2/aws"
  name            = "aws-prod"
  saml2 {
    entity_id = "urn:amazon:webservices"
    acs_url   = "https://signin.aws.amazon.com/saml"
  }
  name_id {
    parts = ["field:requester_email"]
  }
  field {
    name      = "requester_email"
    requester = "email"
  }
`

const (
	roleARNField = `
  field {
    name  = "role_arn"
    value = "arn:aws:iam::123456789012:role/ops"
  }
`
	providerARNField = `
  field {
    name  = "saml_provider_arn"
    value = "arn:aws:iam::123456789012:saml-provider/SplitSecure"
  }
`
	nameIDFormatField = `
  field {
    name  = "name_id_format"
    value = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  }
`
	durationField = `
  field {
    name = "session_duration"
    duration_range {
      min_seconds = 900
      max_seconds = 3600
    }
  }
`
	sessionNameField = `
  field {
    name      = "role_session_name"
    requester = "session_name"
  }
`
)

func awsApp(fields ...string) string {
	return awsAppHead + strings.Join(fields, "") + "}\n"
}

func createdAWSApp() string {
	return awsApp(roleARNField, providerARNField, durationField, nameIDFormatField)
}

// stateOnlyUpdate applies config and requires an in-place update with no server write. The harness then requires an empty plan.
func stateOnlyUpdate(server *vaultServer, config string) tfresource.TestStep {
	var before int

	return tfresource.TestStep{
		PreConfig: func() { before = server.wrote() },
		Config:    config,
		ConfigPlanChecks: tfresource.ConfigPlanChecks{
			PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(appAddress, plancheck.ResourceActionUpdate)},
		},
		Check: func(*terraform.State) error {
			if n := server.wrote() - before; n != 0 {
				return fmt.Errorf("%w: %d calls", errServerWrite, n)
			}

			return nil
		},
	}
}

func TestCorePlanReorderedFieldsUpdateStateOnly(t *testing.T) {
	server := &vaultServer{}

	coreTest(t, server,
		tfresource.TestStep{Config: createdAWSApp()},
		stateOnlyUpdate(server, awsApp(durationField, roleARNField, providerARNField, nameIDFormatField)),
	)
}

func TestCorePlanExplicitImplicitFieldUpdatesStateOnly(t *testing.T) {
	server := &vaultServer{}

	coreTest(t, server,
		tfresource.TestStep{Config: createdAWSApp()},
		stateOnlyUpdate(server, awsApp(roleARNField, providerARNField, durationField, nameIDFormatField, sessionNameField)),
	)
}

func importStep(config string) tfresource.TestStep {
	return tfresource.TestStep{
		Config:          config,
		ResourceName:    appAddress,
		ImportState:     true,
		ImportStateKind: tfresource.ImportBlockWithID,
		ImportStateId:   "vault-1/node-1",
	}
}

func TestCorePlanImportInRecordOrderChangesNothing(t *testing.T) {
	server := &vaultServer{}

	coreTest(t, server,
		tfresource.TestStep{Config: createdAWSApp()},
		importStep(createdAWSApp()),
	)
}

func TestCorePlanImportReorderedPlansAnUpdate(t *testing.T) {
	server := &vaultServer{}

	step := importStep(awsApp(durationField, roleARNField, providerARNField, nameIDFormatField))
	step.ExpectNonEmptyPlan = true
	step.ImportPlanChecks.PreApply = []plancheck.PlanCheck{plancheck.ExpectResourceAction(appAddress, plancheck.ResourceActionUpdate)}

	coreTest(t, server,
		tfresource.TestStep{Config: createdAWSApp()},
		step,
	)
}
