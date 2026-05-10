package saml2

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"

	saml2v1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/saml2/v1"
)

// idpMetadataXML renders the SAML 2.0 EntityDescriptor for an IdPState.
// The output is byte-stable across reads: validUntil is anchored to
// the signing cert's NotAfter so refreshing terraform does not produce
// drift on every plan. Mirrors the rendering rules in priv's
// common/saml2.MetadataOfIDPState; if those diverge, metadata_test.go's
// golden fixture catches it.
func idpMetadataXML(idp *saml2v1.IdPState) ([]byte, error) {
	wantAuthnRequestsSigned := false
	descriptor := idpSSODescriptor{
		ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
		WantAuthnRequestsSigned:    &wantAuthnRequestsSigned,
		KeyDescriptor: []keyDescriptor{
			{
				Use: "signing",
				KeyInfo: keyInfo{
					X509Data: x509Data{
						X509Certificate: base64.StdEncoding.EncodeToString(idp.GetX509Certificate()),
					},
				},
			},
		},
		SingleSignOnService: []endpoint{
			{
				Location: idp.GetSsoUrl(),
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
			},
		},
		NameIDFormat: []string{
			"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
	}

	if idp.GetSsoUrlPost() != "" {
		descriptor.SingleSignOnService = append(descriptor.SingleSignOnService, endpoint{
			Location: idp.GetSsoUrlPost(),
			Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
		})
	}

	validUntil, err := validUntilFromCert(idp.GetX509Certificate())
	if err != nil {
		return nil, fmt.Errorf("computing validUntil from IdP cert: %w", err)
	}
	doc := entityDescriptor{
		EntityID:         idp.GetProviderId(),
		ValidUntil:       validUntil,
		IDPSSODescriptor: &descriptor,
	}

	body, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling IdP metadata: %w", err)
	}

	return append([]byte(xml.Header), body...), nil
}

// validUntilFromCert formats the cert's NotAfter as RFC 3339 so the
// rendered XML is byte-stable across reads (NotAfter is set once at
// mint time). A valid signing cert is a precondition for rendering
// usable metadata, so a parse failure is a hard error rather than a
// silent fallback that masks the real problem.
func validUntilFromCert(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("parsing IdP x509 cert: %w", err)
	}

	return cert.NotAfter.UTC().Format(time.RFC3339), nil
}

// XML struct definitions for the SAML metadata document. Lowercased to
// keep them package-private; renaming would diverge from priv's shapes
// for no gain.

type entityDescriptor struct {
	XMLName          xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID         string            `xml:"entityID,attr"`
	ValidUntil       string            `xml:"validUntil,attr,omitempty"`
	IDPSSODescriptor *idpSSODescriptor `xml:"IDPSSODescriptor,omitempty"`
}

type idpSSODescriptor struct {
	ProtocolSupportEnumeration string          `xml:"protocolSupportEnumeration,attr"`
	WantAuthnRequestsSigned    *bool           `xml:"WantAuthnRequestsSigned,attr,omitempty"`
	KeyDescriptor              []keyDescriptor `xml:"KeyDescriptor,omitempty"`
	SingleSignOnService        []endpoint      `xml:"SingleSignOnService,omitempty"`
	NameIDFormat               []string        `xml:"NameIDFormat,omitempty"`
}

type keyDescriptor struct {
	Use     string  `xml:"use,attr,omitempty"`
	KeyInfo keyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type keyInfo struct {
	X509Data x509Data `xml:"X509Data"`
}

type x509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

type endpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}
