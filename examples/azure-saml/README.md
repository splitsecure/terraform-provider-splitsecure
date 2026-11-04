# Entra ID sign-in with SAML

This module lets a person sign in to Entra ID as one federated user, through SplitSecure with SAML. It federates a custom domain of your tenant with a SplitSecure identity provider. It creates:

- In SplitSecure: a SAML identity provider and a connected app for the user, in a folder of your vault. Terraform creates the folder, named `azure` by default. Set `folder_name` and `parent_folder_id` to change it, and `grantee` to give a principal or group use access to the app.
- In Entra ID: a user in the domain, with a random immutable id.

The app sends a persistent NameID with the user's immutable id, and the user principal name in the `IDPEmail` attribute. Each app is for one user. To add a user, copy the module, or add an `azuread_user` and a `splitsecure_connected_app` for each user.

The app tells Entra ID that the identity provider did the multifactor authentication. The federation command below sets `FederatedIdpMfaBehavior` to `acceptIfMfaDoneByFederatedIdp`, so Entra ID asks for no second factor.

## What Terraform cannot do

The `azuread` provider has no resource for two steps:

- It cannot add or verify a domain. Add the domain in the Entra admin center and verify it with a DNS record before you apply. The module refuses a domain that is not verified.
- It cannot federate a domain. After the apply, run the `federation_command` output in PowerShell, once.

## Before you start

- Terraform 1.11 or later.
- Credentials in the shell for an Entra ID tenant that can create users, for example from `az login`.
- A verified custom domain in the tenant.
- The Microsoft Graph PowerShell module, and the Global Administrator or Domain Name Administrator role.
- A SplitSecure service account with a registered key, allowed to create records in the vault.

> Federation changes sign-in for every user of the domain: each of them signs in through SplitSecure. Federate a domain that only these users use.

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
   vault_name   = "platform"
   domain       = "example.com"
   user_name    = "alice"
   display_name = "Alice"
   ```

3. Run `terraform init` and `terraform apply`. If your vault requires approval to create the identity provider and the connected app, Terraform waits until they are approved.

4. Run the federation command in PowerShell:

   ```bash
   terraform output -raw federation_command
   ```

5. Sign in from SplitSecure with the app, or enter the user principal name at `https://entra.microsoft.com`.

## Remove

Run `terraform destroy`. If your vault requires approval to delete the app and the identity provider, Terraform waits for it. Terraform does not remove the federation. Remove it in PowerShell first with `Remove-MgDomainFederationConfiguration`, or the users of the domain cannot sign in.
