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
