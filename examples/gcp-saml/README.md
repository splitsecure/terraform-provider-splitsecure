# Google Cloud console sign-in with SAML

This module lets your team sign in to the Google Cloud console through SplitSecure with SAML, by workforce identity federation. It creates both sides:

- In SplitSecure: a SAML identity provider and a connected app for the Google Cloud console, in a folder of your vault. Terraform creates the folder, named `gcp` by default. Set `folder_name` and `parent_folder_id` to change it, and `grantee` to give a principal or group use access to the app.
- In Google Cloud: a workforce pool of your organization, a SAML pool provider that trusts the identity provider, and a project role for each user in `user_emails`.

Each sign-in sends the requester's email as the NameID. The pool maps the NameID to the user, so grant roles to the SplitSecure emails of your users. A console session lasts 30 minutes.

## Before you start

- Terraform 1.11 or later.
- Google Cloud credentials in the shell with the Workforce Pool Admin role on the organization, and permission to set IAM on the project.
- The IAM API turned on.
- A SplitSecure service account with a registered key, allowed to create records in the vault.

## Steps

1. Set the SplitSecure credentials in the shell:

   ```bash
   export SPLITSECURE_ORG_S2R=s2r:...:org:...
   export SPLITSECURE_SERVICE_ACCOUNT_S2R=s2r:...:sa:...
   export SPLITSECURE_KEY_ID=...
   export SPLITSECURE_PRIVATE_KEY="$(cat sa.pem)"
   ```

2. Create `terraform.tfvars`:

   ```hcl
   organization_id = "123456789012"
   project_id      = "my-project"
   vault_name      = "platform"
   pool_id         = "acme-splitsecure"
   user_emails     = ["alice@example.com"]
   ```

   A workforce pool id is unique across all of Google Cloud, so choose one for your organization. Google Cloud keeps the id of a deleted pool for 30 days.

3. Run `terraform init` and `terraform apply`. If your vault requires approval to create the identity provider and the connected app, Terraform waits until they are approved.

4. Sign in from SplitSecure with the app, or open the `sign_in_url` output.

## Remove

Run `terraform destroy`. If your vault requires approval to delete the app and the identity provider, Terraform waits for it.
