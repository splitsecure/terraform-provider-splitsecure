# Google Cloud access with OIDC

This module lets your team get Google Cloud service account tokens through SplitSecure with OIDC tokens. It creates both sides:

- In SplitSecure: an OIDC issuer with an ES256 key and a connected app for Google Cloud, in a folder of your vault. Terraform creates the folder, named `gcp` by default. Set `folder_name` and `parent_folder_id` to change it, and `grantee` to give a principal or group use access to the app.
- In Google Cloud: a workload identity pool, a pool provider that trusts the issuer, and a service account with the `roles/viewer` role on the project.

Only this app can act as the service account. Its `roles/iam.workloadIdentityUser` binding names the subject SplitSecure derived for the app. The pool provider accepts one audience: its own full name, which every token of the app carries. The requester chooses a service account token lifetime from 5 to 30 minutes.

## Before you start

- Terraform 1.11 or later.
- Google Cloud credentials in the shell that can enable APIs, and manage workload identity pools, service accounts and IAM in the project.
- A SplitSecure service account with a registered key, allowed to create records in the vault.

## Steps

1. Set the SplitSecure credentials in the shell:

   ```bash
   export SPLITSECURE_ORG_S2R=s2r:...:org:...
   export SPLITSECURE_SERVICE_ACCOUNT_S2R=s2r:...:sa:...
   export SPLITSECURE_KEY_ID=...
   export SPLITSECURE_PRIVATE_KEY="$(cat sa.pem)"
   ```

2. Create `terraform.tfvars` with your project and vault name:

   ```hcl
   project_id = "my-project"
   vault_name = "platform"
   ```

   The other variables have defaults. Google Cloud keeps the id of a deleted pool for 30 days. To apply again within that time, set another `pool_id`.

3. Run `terraform init` and `terraform apply`. If your vault requires approval to create the issuer and the connected app, Terraform waits until they are approved. It creates the service account binding last, because the binding needs the app's subject.

4. Get a token from SplitSecure with the app. Exchange it at the Google Cloud STS for a token of the service account in the `service_account_email` output.

## Remove

Run `terraform destroy`. If your vault requires approval to delete the app and the issuer, Terraform waits for it. The APIs stay on.
