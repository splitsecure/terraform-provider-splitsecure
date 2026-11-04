# AWS sign-in with OIDC

This module lets your team get AWS role sessions through SplitSecure with OIDC tokens. It creates both sides:

- In SplitSecure: an OIDC issuer with an ES256 key and a connected app for AWS, in a folder of your vault. Terraform creates the folder, named `aws` by default. Set `folder_name` and `parent_folder_id` to change it, and `grantee` to give a principal or group use access to the app.
- In AWS: an OIDC provider that trusts the issuer, and a role with read-only access that the app's tokens can assume.

The role trusts only this app. Its trust policy requires the audience `sts.amazonaws.com` and the subject SplitSecure derived for the app. Every token carries a `Team` session tag and the requester's session name as the source identity. The requester chooses a session from 15 minutes up to `max_session_seconds`.

## Before you start

- Terraform 1.11 or later.
- AWS credentials that can manage IAM, in the shell you run Terraform from.
- A SplitSecure service account with a registered key, allowed to create records in the vault.
- Network access from the shell to the issuer URL. Terraform reads its TLS certificate for the AWS OIDC provider.

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

   `role_name`, `max_session_seconds` and `team_tag` have defaults.

3. Run `terraform init` and `terraform apply`. If your vault requires approval to create the issuer and the connected app, Terraform waits until they are approved. It creates the role last, because the role's trust policy needs the app's subject.

4. Get a token from SplitSecure with the app and exchange it with `sts:AssumeRoleWithWebIdentity`. The `role_arn` output is the role it assumes.

## Remove

Run `terraform destroy`. If your vault requires approval to delete the app and the issuer, Terraform waits for it.
