// Package vaultres holds the schema attributes, validators and wiring every vault record resource shares.
package vaultres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	vaultbrowsev1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1/vaultbrowsev1connect"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
)

// ClientFromProviderData extracts the shared client the provider stashes in ProviderData.
// It returns nil before the provider is configured and records a diagnostic on a type mismatch.
func ClientFromProviderData(providerData any, diags *diag.Diagnostics) *client.Client {
	if providerData == nil {
		return nil
	}

	c, ok := providerData.(*client.Client)
	if !ok {
		diags.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("expected *client.Client, got %T", providerData),
		)

		return nil
	}

	return c
}

// ForceNew returns the plan modifiers for an input that lands in the record: any change replaces the resource.
func ForceNew() []planmodifier.String {
	return []planmodifier.String{stringplanmodifier.RequiresReplace()}
}

// ComputedOnce returns the plan modifiers for a server-assigned value that never changes after create.
func ComputedOnce() []planmodifier.String {
	return []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
}

// CommonAttributes returns the attributes every vault record resource carries.
// Callers add their own attributes to the returned map.
func CommonAttributes(kind string) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:      true,
			Description:   "Record id in the vault. Also the import id as vault_id/id.",
			PlanModifiers: ComputedOnce(),
		},
		"vault_id": schema.StringAttribute{
			Required:      true,
			Description:   "Vault the " + kind + " is created in. Changing it replaces the resource.",
			PlanModifiers: ForceNew(),
			Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
		},
		"name": schema.StringAttribute{
			Required:      true,
			Description:   "Human-readable name. Changing it replaces the resource.",
			PlanModifiers: ForceNew(),
			Validators:    []validator.String{stringvalidator.LengthBetween(1, 256)},
		},
		"description": schema.StringAttribute{
			Optional:      true,
			Computed:      true,
			Default:       stringdefault.StaticString(""),
			Description:   "Free-form description. Changing it replaces the resource.",
			PlanModifiers: ForceNew(),
			Validators:    []validator.String{stringvalidator.LengthAtMost(1024)},
		},
		"notification_policy": schema.StringAttribute{
			Optional:      true,
			Computed:      true,
			Default:       stringdefault.StaticString(vaultapi.NotificationPolicyNotifyEveryone),
			Description:   "Who is notified about requests against the " + kind + ". One of: " + strings.Join(vaultapi.NotificationPolicyValues(), ", ") + ". Changing it replaces the resource.",
			PlanModifiers: ForceNew(),
			Validators:    []validator.String{stringvalidator.OneOf(vaultapi.NotificationPolicyValues()...)},
		},
		"folder": schema.ListAttribute{
			ElementType: types.StringType,
			Optional:    true,
			Description: "Folder path from the vault root to place the " + kind + " in, for example [\"terraform\", \"prod\"]. " +
				"Missing folders are created. Unset places it at the vault root. Changing it replaces the resource.",
			PlanModifiers: []planmodifier.List{
				listplanmodifier.RequiresReplace(),
			},
			Validators: []validator.List{
				listvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1)),
			},
		},
		"sensitivity": schema.StringAttribute{
			Optional:      true,
			Computed:      true,
			Description:   "Sensitivity level of the " + kind + ". One of: " + strings.Join(vaultapi.SensitivityValues(), ", ") + ". Changing it replaces the resource.",
			PlanModifiers: append(ComputedOnce(), stringplanmodifier.RequiresReplace()),
			Validators:    []validator.String{stringvalidator.OneOf(vaultapi.SensitivityValues()...)},
		},
		"justification": schema.StringAttribute{
			Optional:    true,
			WriteOnly:   true,
			Description: "Justification shown to approvers when the create needs approval. Write-only and never stored in state.",
			Validators:  []validator.String{stringvalidator.LengthAtMost(4096)},
		},
		"wait": schema.StringAttribute{
			Optional:    true,
			WriteOnly:   true,
			Description: "How long the server holds the create open for approval before Terraform starts polling, as a Go duration such as \"30s\". Defaults to 0. Write-only and never stored in state.",
			Validators:  []validator.String{DurationValidator()},
		},
	}
}

// DurationValidator checks that a string is a non-negative Go duration.
func DurationValidator() validator.String {
	return durationVal{}
}

type durationVal struct{}

func (durationVal) Description(context.Context) string {
	return "must be a non-negative duration such as 30s or 5m"
}

func (v durationVal) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v durationVal) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	raw := req.ConfigValue.ValueString()
	if raw == "" {
		return
	}

	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid duration", v.Description(ctx))
	}
}

// RFC3339Validator checks that a string is an RFC 3339 timestamp.
func RFC3339Validator() validator.String {
	return rfc3339Val{}
}

type rfc3339Val struct{}

func (rfc3339Val) Description(context.Context) string {
	return "must be an RFC 3339 timestamp such as 2030-01-02T15:04:05Z"
}

func (v rfc3339Val) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v rfc3339Val) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	_, err := time.Parse(time.RFC3339, req.ConfigValue.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid timestamp", v.Description(ctx))
	}
}

// SplitImportID splits a vault_id/id import identifier.
func SplitImportID(raw string) (string, string, bool) {
	vaultID, id, ok := strings.Cut(raw, "/")

	return vaultID, id, ok && vaultID != "" && id != ""
}

// WriteOptionsFromConfig reads the write-only justification and wait from the config.
// Write-only values live in the config, never in the plan.
func WriteOptionsFromConfig(ctx context.Context, cfg tfsdk.Config, diags *diag.Diagnostics) *vaultusev1.WriteOptions {
	var justification, wait types.String

	diags.Append(cfg.GetAttribute(ctx, path.Root("justification"), &justification)...)
	diags.Append(cfg.GetAttribute(ctx, path.Root("wait"), &wait)...)

	if diags.HasError() {
		return nil
	}

	opts, err := vaultapi.WriteOptions(justification.ValueString(), wait.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("wait"), "Invalid wait", err.Error())

		return nil
	}

	return opts
}

// DestroyOptions builds the write options for a delete, which has no config to read them from.
func DestroyOptions(kind, name string) *vaultusev1.WriteOptions {
	return &vaultusev1.WriteOptions{Justification: fmt.Sprintf("terraform destroy of %s %q", kind, name)}
}

// EnsureFolder creates the folder path configured on a resource and returns its node id, or "" for the vault root.
func EnsureFolder(ctx context.Context, browse vaultbrowsev1connect.VaultBrowseServiceClient, vaultID string, folder types.List, diags *diag.Diagnostics) (string, bool) {
	var segments []string

	diags.Append(folder.ElementsAs(ctx, &segments, false)...)

	if diags.HasError() {
		return "", false
	}

	nodeID, err := vaultapi.EnsureFolder(ctx, browse, vaultID, segments)
	if err != nil {
		diags.AddAttributeError(path.Root("folder"), "Preparing folder", err.Error())

		return "", false
	}

	return nodeID, true
}
