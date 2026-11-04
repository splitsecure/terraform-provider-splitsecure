# AWS sign-in with SAML

This module lets your team sign in to an AWS role through SplitSecure with SAML. It creates both sides:

- In SplitSecure: a SAML identity provider and a connected app for the AWS console, in a folder of your vault. Terraform creates the folder, named `aws` by default. Set `folder_name` and `parent_folder_id` to change it, and `grantee` to give a principal or group use access to the app.
- In AWS: a SAML provider that trusts the identity provider, and a role with read-only access that the app signs in to.

Each sign-in uses the requester's email as the NameID. The requester chooses a session from 15 minutes to 1 hour, and every session carries a `Team` tag.

## Before you start

- Terraform 1.11 or later.
- AWS credentials that can manage IAM, in the shell you run Terraform from.
- A SplitSecure service account with a registered key, allowed to create records in the vault.

## Steps

1. Set the SplitSecure credentials in the shell:

   ```bash
   export SPLITSECURE_ORG_S2R=s2r:...:org:...
   export SPLITSECURE_SERVICE_ACCOUNT_S2R=s2r:...:sa:...
   export SPLITSECURE_KEY_ID=...
   export SPLITSECURE_PRIVATE_KEY="$(cat sa.pem)"
   ```

2. Create `terraform.tfvars` with your region and vault name:

   ```hcl
   aws_region = "us-east-1"
   vault_name = "platform"
   ```

   `role_name` and `team_tag` have defaults.

3. Run `terraform init` and `terraform apply`. If your vault requires approval to create the identity provider and the connected app, Terraform waits until they are approved.

4. Sign in from SplitSecure with the app. The `role_arn` output is the role you land in.

## Remove

Run `terraform destroy`. If your vault requires approval to delete the app and the identity provider, Terraform waits for it.
