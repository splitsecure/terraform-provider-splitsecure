//go:build tools

// Package tools pins build-time tool dependencies so go install / go run
// resolves them through the regular module graph. Excluded from normal
// builds via the "tools" build tag.
package tools

import (
	// tfplugindocs generates the docs/ tree consumed by the Terraform
	// Registry. Wired through main.go's go:generate directive.
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)
