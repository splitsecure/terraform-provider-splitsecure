package connectedapp

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	samlv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/oasis/saml/v2"
)

func pathField() path.Path { return path.Root("field") }

const multiACSMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/saml" validUntil="2030-01-02T03:04:05Z" cacheDuration="P1DT2H">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>MIIBcertificate</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://sp.example.com/slo"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0" isDefault="true"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs2" index="1"/>
  </SPSSODescriptor>
  <Organization>
    <OrganizationName xml:lang="en">Example</OrganizationName>
    <OrganizationDisplayName xml:lang="en">Example Inc</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">https://example.com</OrganizationURL>
  </Organization>
  <ContactPerson contactType="technical">
    <GivenName>Ada</GivenName>
    <EmailAddress>ada@example.com</EmailAddress>
  </ContactPerson>
</EntityDescriptor>
`

// reformattedMultiACSMetadata is the same metadata with prefixes, another attribute order and no indentation.
const reformattedMultiACSMetadata = `<md:EntityDescriptor cacheDuration="P1DT2H" validUntil="2030-01-02T03:04:05Z" entityID="https://sp.example.com/saml"` +
	` xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
	`<md:SPSSODescriptor WantAssertionsSigned="true" AuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
	`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBcertificate</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
	`<md:SingleLogoutService Location="https://sp.example.com/slo" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>` +
	`<md:AssertionConsumerService isDefault="true" index="0" Location="https://sp.example.com/acs" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>` +
	`<md:AssertionConsumerService index="1" Location="https://sp.example.com/acs2" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>` +
	`</md:SPSSODescriptor><md:Organization><md:OrganizationName xml:lang="en">Example</md:OrganizationName>` +
	`<md:OrganizationDisplayName xml:lang="en">Example Inc</md:OrganizationDisplayName><md:OrganizationURL xml:lang="en">https://example.com</md:OrganizationURL></md:Organization>` +
	`<md:ContactPerson contactType="technical"><md:GivenName>Ada</md:GivenName><md:EmailAddress>ada@example.com</md:EmailAddress></md:ContactPerson></md:EntityDescriptor>`

func wantMultiACS() *samlv2.Metadata {
	return &samlv2.Metadata{Content: &samlv2.Metadata_EntityDescriptor{EntityDescriptor: &samlv2.EntityDescriptor{
		EntityId:      "https://sp.example.com/saml",
		ValidUntil:    timestamppb.New(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)),
		CacheDuration: durationpb.New(26 * time.Hour),
		SpSsoDescriptor: []*samlv2.SPSSODescriptor{{
			Base: &samlv2.SSODescriptorType{
				Base: &samlv2.RoleDescriptorType{
					ProtocolSupportEnumeration: []string{"urn:oasis:names:tc:SAML:2.0:protocol"},
					KeyDescriptor: []*samlv2.KeyDescriptor{{
						Use: samlv2.KeyType_KEY_TYPE_SIGNING, KeyInfo: &samlv2.KeyInfo{X509Certificate: []byte("MIIBcertificate")},
					}},
				},
				SingleLogoutService: []*samlv2.Endpoint{{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", Location: "https://sp.example.com/slo"}},
			},
			AuthnRequestsSigned:  true,
			WantAssertionsSigned: true,
			AssertionConsumerService: []*samlv2.IndexedEndpoint{
				{Base: &samlv2.Endpoint{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://sp.example.com/acs"}, IsDefault: true},
				{Base: &samlv2.Endpoint{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://sp.example.com/acs2"}, Index: 1},
			},
		}},
		Organization: &samlv2.Organization{
			OrganizationName:        []*samlv2.LocalizedName{{Value: "Example", Lang: "en"}},
			OrganizationDisplayName: []*samlv2.LocalizedName{{Value: "Example Inc", Lang: "en"}},
			OrganizationUrl:         []*samlv2.LocalizedURI{{Value: "https://example.com", Lang: "en"}},
		},
		ContactPerson: []*samlv2.ContactPerson{{ContactType: samlv2.ContactType_CONTACT_TYPE_TECHNICAL, GivenName: "Ada", EmailAddress: []string{"ada@example.com"}}},
	}}}
}

func TestParseMetadataReadsAMultiACSDocument(t *testing.T) {
	t.Parallel()

	got, err := parseMetadata(multiACSMetadata)
	if err != nil {
		t.Fatal(err)
	}

	assertProtoEqual(t, got, wantMultiACS())
}

func TestParseMetadataIgnoresFormatting(t *testing.T) {
	t.Parallel()

	got, err := parseMetadata(reformattedMultiACSMetadata)
	if err != nil {
		t.Fatal(err)
	}

	assertProtoEqual(t, got, wantMultiACS())
}

func TestRenderMetadataRoundTrips(t *testing.T) {
	t.Parallel()

	rendered, err := renderMetadata(wantMultiACS())
	if err != nil {
		t.Fatal(err)
	}

	back, err := parseMetadata(rendered)
	if err != nil {
		t.Fatalf("parsing the rendered metadata: %v\n%s", err, rendered)
	}

	assertProtoEqual(t, back, wantMultiACS())
}

func TestParseMetadataReadsMicrosoftFederationMetadata(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("testdata/microsoft-federation-metadata.xml")
	if err != nil {
		t.Fatal(err)
	}

	md, err := parseMetadata(string(raw))
	if err != nil {
		t.Fatal(err)
	}

	ed := md.GetEntityDescriptor()
	acs := ed.GetSpSsoDescriptor()[0].GetAssertionConsumerService()

	if ed.GetEntityId() != "urn:federation:MicrosoftOnline" || len(acs) != 3 || acs[0].GetBase().GetLocation() != "https://login.microsoftonline.com/login.srf" || !acs[0].GetIsDefault() {
		t.Errorf("entity id %q, ACS %v", ed.GetEntityId(), acs)
	}

	_, err = renderMetadata(md)
	if err != nil {
		t.Errorf("rendering the parsed metadata: %v", err)
	}
}

func TestParseMetadataRefuses(t *testing.T) {
	t.Parallel()

	for name, tt := range map[string]struct {
		raw  string
		want error
	}{
		"not XML":                {"entity", errNotMetadata},
		"no entityID":            {`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`, errNotMetadata},
		"another root":           {`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>`, errNotMetadata},
		"a cache of some months": {`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x" cacheDuration="P1M"/>`, errCacheDuration},
	} {
		_, err := parseMetadata(tt.raw)
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tt.want)
		}
	}
}

func TestRenderMetadataRefusesWhatXMLCannotCarry(t *testing.T) {
	t.Parallel()

	md := proto.CloneOf(wantMultiACS())
	md.GetEntityDescriptor().Signature = []byte("signed")

	_, err := renderMetadata(md)
	if !errors.Is(err, errUnwritableParts) {
		t.Errorf("err = %v, want errUnwritableParts", err)
	}
}
