# End-to-end smoke test against the splitsecure provider on a real backend.
#
# Auth: export SPLITSECURE_BEARER_TOKEN (s2ak_...) before running.

.PHONY: init plan apply destroy clean help

help:
	@echo "Targets:"
	@echo "  init      terraform init (pulls splitsecure provider from the registry)"
	@echo "  plan      terraform plan"
	@echo "  apply     terraform apply"
	@echo "  destroy   terraform destroy"
	@echo "  clean     remove .terraform, lock file, and tfstate"

init:
	terraform init

plan:
	terraform plan

apply:
	terraform apply

destroy:
	terraform destroy

clean:
	rm -rf .terraform .terraform.lock.hcl terraform.tfstate terraform.tfstate.backup
