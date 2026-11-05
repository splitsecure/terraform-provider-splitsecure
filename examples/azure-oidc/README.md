# Entra ID access with OIDC

This module lets your team get Entra ID application tokens through SplitSecure with OIDC tokens. It creates both sides:

- In SplitSecure: an OIDC issuer with an RS256 key and a connected app for Entra ID, in a folder of your vault. Terraform creates the folder, named `azure` by default. Set `folder_name` and `parent_folder_id` to change it, and `grantee` to give a principal or group use access to the app.
- In Entra ID: an application, its service principal, and a federated identity credential that trusts the app's tokens.

Entra ID checks three values of each token against the credential: the issuer URL of the issuer, the subject SplitSecure derived for the app, and the audience `api://AzureADTokenExchange`. Entra ID takes RS256 tokens only, so the app uses the RS256 key of the issuer. The requester chooses a token lifetime from 5 to 30 minutes. Entra ID sets the lifetime of the access token it returns in the exchange, 60 to 90 minutes by default.

The module grants the service principal no Azure roles. Grant them with the `service_principal_object_id` output, in the Azure portal or with the `azurerm` provider.

## Before you start

- Terraform 1.11 or later.
- Credentials in the shell for an Entra ID tenant that can create applications, for example from `az login`.
- A SplitSecure service account with a registered key, allowed to create records in the vault.
- A SplitSecure deployment that signs Entra ID app tokens with RS256. An older deployment refuses the app with a signing algorithm error.

## Steps

1. Set the SplitSecure credentials in the shell:

   ```bash
   export SPLITSECURE_ORG_S2R=s2r:...:org:...
   export SPLITSECURE_SERVICE_ACCOUNT_S2R=s2r:...:sa:...
   export SPLITSECURE_KEY_ID=...
   export SPLITSECURE_PRIVATE_KEY="$(cat sa.pem)"
   ```

2. Create `terraform.tfvars` with your vault name:

   ```hcl
   vault_name = "platform"
   ```

   The other variables have defaults.

3. Run `terraform init` and `terraform apply`. If your vault requires approval to create the issuer and the connected app, Terraform waits until they are approved. It creates the federated identity credential last, because the credential needs the app's subject.

4. Get a token from SplitSecure with the app. Exchange it at Entra ID as a client assertion for the `client_id` output in the `tenant_id` output.

## Remove

Run `terraform destroy`. If your vault requires approval to delete the app and the issuer, Terraform waits for it.
