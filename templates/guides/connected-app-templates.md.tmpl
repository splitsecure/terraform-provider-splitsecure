---
page_title: "Connected app templates"
subcategory: "Guides"
description: |-
  The templates a splitsecure_connected_app can use, and the fields each template takes.
---

# Connected app templates

Set `template` on a `splitsecure_connected_app` to one of the templates on this page. A SAML template takes a `saml2` block. An OIDC template takes an `oidc` block. Each `field` block sets one field of the template. Fields that the template fills itself are marked in the tables, and you do not set them.

## Field sources

A field block sets exactly one source.

| Source | In the field block |
|---|---|
| Fixed text | `value = "..."` |
| Fixed list of text | `values = ["..."]` |
| Fixed duration | `seconds = 3600` |
| Fixed JSON object | `json = jsonencode({...})` |
| Text that the requester chooses at each sign-in | `choices = ["..."]`, and optionally `default_value` |
| Duration that the requester chooses at each sign-in | a `duration_range` block with `min_seconds`, `max_seconds`, and optionally `default_seconds` |
| The identity of the requester | `requester = "email"` or `requester = "session_name"`, and optionally `suffix` |
| A value that SplitSecure derives once at app creation | `derived = "at_creation"` |
| A value that SplitSecure derives again at each sign-in | `derived = "per_sign_in"` |

A repeatable field takes one field block for each instance. Give each instance a `key`. The tables show where each instance goes.

## SAML NameID

Set `name_id_format`, then give the NameID with the `name_id` field or with a `name_id` block.

- A transient NameID uses `name_id` with `derived = "per_sign_in"`.
- A persistent NameID uses `name_id` with `value` or `derived = "at_creation"`.
- An email or unspecified NameID uses `name_id` with `value` or `choices`, or a `name_id` block. AWS does not accept a NameID that the requester chooses at sign-in.
- In a `name_id` block, a part that starts with `field:` is the value of that field, and any other part is literal text. The parts can be literal text, fixed fields, and requester fields, such as `requester_email` with `requester = "email"`.

The provider refuses an app that has no NameID.

## OIDC subject and key

- The AWS, Google Cloud, and Entra ID templates derive the subject at app creation. Read it from `derived_values["subject"]` and require it in the trust policy of the cloud.
- The `key_id` in the `oidc` block names one key of the issuer. Take it from the `keys` of the issuer, such as `one([for k in splitsecure_oidc_issuer.main.keys : k.key_id if k.alg == "ES256"])`. The key must use an algorithm that the template accepts.

## Templates

### AWS (OIDC)

`template = "oidc/aws"`

| OIDC token | Value |
|---|---|
| Signing algorithm | `ES256`, `ES384` |
| `sub` | `subject` |
| `aud` | `"sts.amazonaws.com"` |
| Lifetime | 600 seconds, the time the client has to exchange the token |
| `jti` | `token_id` |
| Session asked of the cloud | `session_duration`, not in the token |
| Claim `https://aws.amazon.com/roles` | `role_arn`, as a list |
| Claim `https://aws.amazon.com/source_identity` | `source_identity` |
| Claim `https://aws.amazon.com/tags` > `principal_tags` > `SplitSecureTokenId` | `token_id`, as a list |
| Claim `https://aws.amazon.com/tags` > `principal_tags` > `<key>` | each `session_tag` instance, as a list |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `role_arn` | text | yes | `value` |  |
| `subject` | text | filled by the template | `derived = "at_creation"` |  |
| `session_duration` | duration | yes | `seconds`, `duration_range` | From 900 to 43200 seconds. |
| `source_identity` | text | filled by the template | `requester = "session_name"` |  |
| `token_id` | text | filled by the template | `derived = "per_sign_in"` |  |
| `session_tag` | text | no | `value`, `choices`, `requester = "session_name"`, `requester = "email"` | Repeatable. Give each instance a `key`. |

### Microsoft Entra ID

`template = "oidc/azure"`

| OIDC token | Value |
|---|---|
| Signing algorithm | `RS256` |
| `sub` | `subject` |
| `aud` | `"api://AzureADTokenExchange"` |
| Lifetime | `lifetime` |
| `jti` | `token_id` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `tenant_id` | text | yes | `value` |  |
| `client_id` | text | yes | `value` |  |
| `subject` | text | filled by the template | `derived = "at_creation"` |  |
| `lifetime` | duration | yes | `seconds`, `duration_range` | From 60 to 3600 seconds. |
| `token_id` | text | filled by the template | `derived = "per_sign_in"` |  |

### Google Cloud

`template = "oidc/gcp"`

| OIDC token | Value |
|---|---|
| Signing algorithm | `ES256` |
| `sub` | `subject` |
| `aud` | `"https://iam.googleapis.com/projects/"` + `project_number` + `"/locations/global/workloadIdentityPools/"` + `pool_id` + `"/providers/"` + `provider_id` |
| Lifetime | 600 seconds, the time the client has to exchange the token |
| `jti` | `token_id` |
| Session asked of the cloud | `access_token_lifetime`, not in the token |
| Claim `<key>` | each `claim` instance |
| Claim `<key>` | each `claim_list` instance |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `project_number` | text | yes | `value` |  |
| `pool_id` | text | yes | `value` |  |
| `provider_id` | text | yes | `value` |  |
| `service_account_email` | text | yes | `value` |  |
| `subject` | text | filled by the template | `derived = "at_creation"` |  |
| `access_token_lifetime` | duration | yes | `seconds`, `duration_range` | From 60 to 43200 seconds. |
| `token_id` | text | filled by the template | `derived = "per_sign_in"` |  |
| `claim` | text | no | `value`, `choices`, `requester = "session_name"`, `requester = "email"` | Repeatable. Give each instance a `key`. |
| `claim_list` | list of text | no | `values`, `choices` | Repeatable. Give each instance a `key`. |

### Generic OIDC

`template = "oidc/generic"`

| OIDC token | Value |
|---|---|
| Signing algorithm | any key of the issuer |
| `sub` | `subject` |
| `aud` | `audience` |
| Lifetime | `lifetime` |
| `jti` | `token_id` |
| Top-level claims | `claims` |
| Claim `<key>` | each `claim` instance |
| Claim `<key>` | each `claim_list` instance |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `audience` | text | yes | `value` |  |
| `subject` | text | yes | `value`, `derived = "at_creation"` |  |
| `claims` | JSON object | no | `json` |  |
| `lifetime` | duration | yes | `seconds`, `duration_range` | From 60 to 43200 seconds. |
| `token_id` | text | filled by the template | `derived = "per_sign_in"` |  |
| `claim` | text | no | `value`, `choices`, `requester = "session_name"`, `requester = "email"` | Repeatable. Give each instance a `key`. |
| `claim_list` | list of text | no | `values`, `choices` | Repeatable. Give each instance a `key`. |

### AWS (SAML)

`template = "saml2/aws"`

| SAML assertion | Value |
|---|---|
| Audience | `https://signin.aws.amazon.com/saml` |
| NameID format | `name_id_format` |
| NameID | `name_id` |
| Attribute `https://aws.amazon.com/SAML/Attributes/Role` | `role_arn` + `","` + `saml_provider_arn` |
| Attribute `https://aws.amazon.com/SAML/Attributes/RoleSessionName` | `role_session_name` |
| Attribute `https://aws.amazon.com/SAML/Attributes/SessionDuration` | `session_duration` in seconds |
| Attribute `https://aws.amazon.com/SAML/Attributes/PrincipalTag:<key>` | each `session_tag` instance |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `saml_provider_arn` | text | yes | `value` |  |
| `role_arn` | text | yes | `value` |  |
| `session_duration` | duration | yes | `seconds`, `duration_range` | From 900 to 43200 seconds. |
| `role_session_name` | text | filled by the template | `requester = "session_name"` |  |
| `session_tag` | text | no | `value`, `choices`, `requester = "session_name"`, `requester = "email"` | Repeatable. Give each instance a `key`. |
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |

### Cloudflare

`template = "saml2/cloudflare"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |
| Attribute `email` | `name_id` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |
| `sso_endpoint` | text | yes | `value` |  |

### Google Cloud Platform

`template = "saml2/gcp"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |

### Generic SAML

`template = "saml2/generic"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |
| Attribute `<key>` | each `attribute` instance |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |
| `attribute` | list of text | no | `values` | Repeatable. Give each instance a `key`. |

### Google Workspace

`template = "saml2/google-workspace"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |

### Google Workspace Legacy

`template = "saml2/google-workspace-legacy"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |
| Attribute `Email` | `name_id` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |

### Iru

`template = "saml2/iru"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |

### Entra ID

`template = "saml2/microsoft-entra-id"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |
| Attribute `IDPEmail` | `user_principal_name` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |
| `user_principal_name` | text | yes | `value` |  |

### Okta

`template = "saml2/okta"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |
| Attribute `session.amr` | `session_amr` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |
| `session_amr` | list of text | yes | `values` | One of `mfa`, `user`, `hwk`, `mca`. |

### Oracle Cloud

`template = "saml2/oracle-cloud"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |
| Attribute `Username` | `name_id` |
| Attribute `Email` | `email` |
| Attribute `FirstName` | `first_name` |
| Attribute `LastName` | `last_name` |
| Attribute `Group` | `group` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |
| `email` | text | no | `value` |  |
| `first_name` | text | no | `value` |  |
| `last_name` | text | no | `value` |  |
| `group` | text | no | `value` |  |

### PagerDuty

`template = "saml2/pagerduty"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |
| Attribute `email` | `name_id` |
| Attribute `name` | `full_name` |
| Attribute `role` | `role` |
| Attribute `jobresponsibilities` | `job_responsibilities` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |
| `full_name` | text | no | `value` |  |
| `role` | text | no | `value` | One of `admin`, `user`, `limited_user`, `observer`, `read_only_user`, `read_only_limited_user`, `restricted_access`. |
| `job_responsibilities` | text | no | `value` |  |

### Rapid7

`template = "saml2/rapid7"`

| SAML assertion | Value |
|---|---|
| Audience | the entity ID in the `saml2` block |
| NameID format | `name_id_format` |
| NameID | `name_id` |
| Attribute `Email` | `name_id` |
| Attribute `FirstName` | `first_name` |
| Attribute `LastName` | `last_name` |
| Attribute `rbacGroups` | `rbac_groups` |

| Field | Type | Required | Sources | Notes |
|---|---|---|---|---|
| `name_id_format` | text | yes | `value` | One of `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. |
| `name_id` | text | no | `value`, `choices`, `derived = "at_creation"`, `derived = "per_sign_in"` |  |
| `requester_email` | text | no | `requester = "email"` |  |
| `requester_session_name` | text | no | `requester = "session_name"` |  |
| `relay_state` | text | yes | `value` |  |
| `first_name` | text | no | `value` |  |
| `last_name` | text | no | `value` |  |
| `rbac_groups` | list of text | no | `values` |  |
