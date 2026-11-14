package connectedapp

import (
	samlv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/oasis/saml/v2"
)

const bindingHTTPPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

// MinimalSPMetadata returns the smallest SP metadata for an entity id and one
// default HTTP-POST assertion consumer service.
func MinimalSPMetadata(entityID, acsURL string) *samlv2.Metadata {
	return &samlv2.Metadata{Content: &samlv2.Metadata_EntityDescriptor{EntityDescriptor: &samlv2.EntityDescriptor{
		EntityId: entityID,
		SpSsoDescriptor: []*samlv2.SPSSODescriptor{{
			AssertionConsumerService: []*samlv2.IndexedEndpoint{{
				Base:      &samlv2.Endpoint{Binding: bindingHTTPPost, Location: acsURL},
				IsDefault: true,
			}},
		}},
	}}}
}
