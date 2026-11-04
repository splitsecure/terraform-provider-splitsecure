package connectedapp

import (
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	samlv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/oasis/saml/v2"
)

var (
	errNotMetadata     = errors.New("metadata_xml is not a SAML 2.0 EntityDescriptor with an entityID")
	errCacheDuration   = errors.New("cacheDuration is not an ISO 8601 duration of days, hours, minutes and seconds")
	errUnwritableParts = errors.New("the service provider metadata holds parts that metadata_xml cannot carry")
)

// xmlEntityDescriptor is SAML metadata as far as the parser reads it, with the SAML schema's element and attribute names.
type xmlEntityDescriptor struct {
	XMLName          xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID         string               `xml:"entityID,attr"`
	ID               string               `xml:"ID,attr,omitempty"`
	ValidUntil       string               `xml:"validUntil,attr,omitempty"`
	CacheDuration    string               `xml:"cacheDuration,attr,omitempty"`
	IDPSSODescriptor *xmlIDPSSODescriptor `xml:"IDPSSODescriptor,omitempty"`
	SPSSODescriptor  *xmlSPSSODescriptor  `xml:"SPSSODescriptor,omitempty"`
	Organization     *xmlOrganization     `xml:"Organization,omitempty"`
	ContactPerson    []xmlContactPerson   `xml:"ContactPerson,omitempty"`
}

type xmlIDPSSODescriptor struct {
	ProtocolSupportEnumeration string             `xml:"protocolSupportEnumeration,attr"`
	WantAuthnRequestsSigned    *bool              `xml:"WantAuthnRequestsSigned,attr,omitempty"`
	KeyDescriptor              []xmlKeyDescriptor `xml:"KeyDescriptor,omitempty"`
	SingleSignOnService        []xmlEndpoint      `xml:"SingleSignOnService,omitempty"`
	SingleLogoutService        []xmlEndpoint      `xml:"SingleLogoutService,omitempty"`
	NameIDFormat               []string           `xml:"NameIDFormat,omitempty"`
}

type xmlSPSSODescriptor struct {
	ProtocolSupportEnumeration string               `xml:"protocolSupportEnumeration,attr"`
	AuthnRequestsSigned        *bool                `xml:"AuthnRequestsSigned,attr,omitempty"`
	WantAssertionsSigned       *bool                `xml:"WantAssertionsSigned,attr,omitempty"`
	KeyDescriptor              []xmlKeyDescriptor   `xml:"KeyDescriptor,omitempty"`
	AssertionConsumerService   []xmlIndexedEndpoint `xml:"AssertionConsumerService,omitempty"`
	SingleLogoutService        []xmlEndpoint        `xml:"SingleLogoutService,omitempty"`
}

type xmlKeyDescriptor struct {
	Use     string     `xml:"use,attr,omitempty"`
	KeyInfo xmlKeyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type xmlKeyInfo struct {
	X509Data struct {
		X509Certificate string `xml:"X509Certificate"`
	} `xml:"X509Data"`
}

type xmlEndpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}

type xmlIndexedEndpoint struct {
	xmlEndpoint

	Index     int   `xml:"index,attr"`
	IsDefault *bool `xml:"isDefault,attr,omitempty"`
}

type xmlOrganization struct {
	OrganizationName        []xmlLocalized `xml:"OrganizationName"`
	OrganizationDisplayName []xmlLocalized `xml:"OrganizationDisplayName"`
	OrganizationURL         []xmlLocalized `xml:"OrganizationURL"`
}

type xmlContactPerson struct {
	ContactType     string   `xml:"contactType,attr"`
	Company         string   `xml:"Company,omitempty"`
	GivenName       string   `xml:"GivenName,omitempty"`
	SurName         string   `xml:"SurName,omitempty"`
	EmailAddress    []string `xml:"EmailAddress,omitempty"`
	TelephoneNumber []string `xml:"TelephoneNumber,omitempty"`
}

type xmlLocalized struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}

// parseMetadata reads SAML 2.0 metadata as the web client does: one EntityDescriptor, its first IdP and SP descriptor,
// organization and contacts, with each certificate kept as the element's text.
func parseMetadata(raw string) (*samlv2.Metadata, error) {
	var ed xmlEntityDescriptor

	err := xml.Unmarshal([]byte(raw), &ed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotMetadata, err)
	}

	if ed.EntityID == "" {
		return nil, errNotMetadata
	}

	entity, err := entityFromXML(&ed)
	if err != nil {
		return nil, err
	}

	return &samlv2.Metadata{Content: &samlv2.Metadata_EntityDescriptor{EntityDescriptor: entity}}, nil
}

func entityFromXML(ed *xmlEntityDescriptor) (*samlv2.EntityDescriptor, error) {
	out := &samlv2.EntityDescriptor{EntityId: ed.EntityID, Id: ed.ID}

	if ed.ValidUntil != "" {
		t, err := time.Parse(time.RFC3339, ed.ValidUntil)
		if err != nil {
			return nil, fmt.Errorf("parsing validUntil: %w", err)
		}

		out.ValidUntil = timestamppb.New(t)
	}

	if ed.CacheDuration != "" {
		d, err := parseISODuration(ed.CacheDuration)
		if err != nil {
			return nil, err
		}

		out.CacheDuration = durationpb.New(d)
	}

	if ed.IDPSSODescriptor != nil {
		out.IdpSsoDescriptor = []*samlv2.IDPSSODescriptor{idpFromXML(ed.IDPSSODescriptor)}
	}

	if ed.SPSSODescriptor != nil {
		out.SpSsoDescriptor = []*samlv2.SPSSODescriptor{spFromXML(ed.SPSSODescriptor)}
	}

	if ed.Organization != nil {
		out.Organization = organizationFromXML(ed.Organization)
	}

	for i := range ed.ContactPerson {
		out.ContactPerson = append(out.ContactPerson, contactFromXML(&ed.ContactPerson[i]))
	}

	return out, nil
}

func idpFromXML(x *xmlIDPSSODescriptor) *samlv2.IDPSSODescriptor {
	base := ssoBase(x.ProtocolSupportEnumeration, x.KeyDescriptor, x.SingleLogoutService)
	base.NameIdFormat = x.NameIDFormat

	out := &samlv2.IDPSSODescriptor{Base: base, WantAuthnRequestsSigned: x.WantAuthnRequestsSigned != nil && *x.WantAuthnRequestsSigned}

	for _, sso := range x.SingleSignOnService {
		out.SingleSignOnService = append(out.SingleSignOnService, endpointFromXML(sso))
	}

	return out
}

func spFromXML(x *xmlSPSSODescriptor) *samlv2.SPSSODescriptor {
	out := &samlv2.SPSSODescriptor{
		Base:                 ssoBase(x.ProtocolSupportEnumeration, x.KeyDescriptor, x.SingleLogoutService),
		AuthnRequestsSigned:  x.AuthnRequestsSigned != nil && *x.AuthnRequestsSigned,
		WantAssertionsSigned: x.WantAssertionsSigned != nil && *x.WantAssertionsSigned,
	}

	for _, acs := range x.AssertionConsumerService {
		out.AssertionConsumerService = append(out.AssertionConsumerService, &samlv2.IndexedEndpoint{
			Base:      endpointFromXML(acs.xmlEndpoint),
			Index:     uint32(max(acs.Index, 0)), //nolint:gosec // an index never nears the uint32 bound.
			IsDefault: acs.IsDefault != nil && *acs.IsDefault,
		})
	}

	return out
}

func ssoBase(protocols string, keys []xmlKeyDescriptor, logout []xmlEndpoint) *samlv2.SSODescriptorType {
	base := &samlv2.SSODescriptorType{Base: &samlv2.RoleDescriptorType{ProtocolSupportEnumeration: []string{protocols}}}

	for _, k := range keys {
		base.Base.KeyDescriptor = append(base.Base.KeyDescriptor, &samlv2.KeyDescriptor{
			Use:     keyUseFromXML(k.Use),
			KeyInfo: &samlv2.KeyInfo{X509Certificate: []byte(k.KeyInfo.X509Data.X509Certificate)},
		})
	}

	for _, e := range logout {
		base.SingleLogoutService = append(base.SingleLogoutService, endpointFromXML(e))
	}

	return base
}

func endpointFromXML(e xmlEndpoint) *samlv2.Endpoint {
	return &samlv2.Endpoint{Binding: e.Binding, Location: e.Location, ResponseLocation: e.ResponseLocation}
}

func keyUseFromXML(use string) samlv2.KeyType {
	switch use {
	case "signing":
		return samlv2.KeyType_KEY_TYPE_SIGNING
	case "encryption":
		return samlv2.KeyType_KEY_TYPE_ENCRYPTION
	default:
		return samlv2.KeyType_KEY_TYPE_UNSPECIFIED
	}
}

func organizationFromXML(x *xmlOrganization) *samlv2.Organization {
	out := &samlv2.Organization{}

	for _, n := range x.OrganizationName {
		out.OrganizationName = append(out.OrganizationName, &samlv2.LocalizedName{Value: n.Value, Lang: n.Lang})
	}

	for _, n := range x.OrganizationDisplayName {
		out.OrganizationDisplayName = append(out.OrganizationDisplayName, &samlv2.LocalizedName{Value: n.Value, Lang: n.Lang})
	}

	for _, u := range x.OrganizationURL {
		out.OrganizationUrl = append(out.OrganizationUrl, &samlv2.LocalizedURI{Value: u.Value, Lang: u.Lang})
	}

	return out
}

func contactTypes() map[string]samlv2.ContactType {
	return map[string]samlv2.ContactType{
		"technical":      samlv2.ContactType_CONTACT_TYPE_TECHNICAL,
		"support":        samlv2.ContactType_CONTACT_TYPE_SUPPORT,
		"administrative": samlv2.ContactType_CONTACT_TYPE_ADMINISTRATIVE,
		"billing":        samlv2.ContactType_CONTACT_TYPE_BILLING,
		"other":          samlv2.ContactType_CONTACT_TYPE_OTHER,
	}
}

func contactFromXML(x *xmlContactPerson) *samlv2.ContactPerson {
	return &samlv2.ContactPerson{
		ContactType:     contactTypes()[x.ContactType],
		Company:         x.Company,
		GivenName:       x.GivenName,
		Surname:         x.SurName,
		EmailAddress:    x.EmailAddress,
		TelephoneNumber: x.TelephoneNumber,
	}
}

var isoDuration = regexp.MustCompile(`^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// parseISODuration reads the weeks, days, hours, minutes and seconds of an ISO 8601 duration. Years and months have no fixed length, so they are refused.
func parseISODuration(s string) (time.Duration, error) {
	m := isoDuration.FindStringSubmatch(s)
	if m == nil || s == "P" || strings.HasSuffix(s, "T") {
		return 0, fmt.Errorf("%w: %q", errCacheDuration, s)
	}

	units := []time.Duration{7 * 24 * time.Hour, 24 * time.Hour, time.Hour, time.Minute, time.Second}

	var total time.Duration

	for i, unit := range units {
		if m[i+1] == "" {
			continue
		}

		n, err := strconv.ParseFloat(m[i+1], 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %q", errCacheDuration, s)
		}

		total += time.Duration(n * float64(unit))
	}

	return total, nil
}

// renderMetadata writes metadata as XML that parseMetadata reads back to the same message, or refuses.
func renderMetadata(md *samlv2.Metadata) (string, error) {
	ed := md.GetEntityDescriptor()
	if ed == nil {
		return "", errUnwritableParts
	}

	x := entityAttrsToXML(ed)

	if idps := ed.GetIdpSsoDescriptor(); len(idps) > 0 {
		x.IDPSSODescriptor = idpToXML(idps[0])
	}

	if sps := ed.GetSpSsoDescriptor(); len(sps) > 0 {
		x.SPSSODescriptor = spToXML(sps[0])
	}

	if org := ed.GetOrganization(); org != nil {
		x.Organization = organizationToXML(org)
	}

	for _, c := range ed.GetContactPerson() {
		x.ContactPerson = append(x.ContactPerson, contactToXML(c))
	}

	out, err := xml.MarshalIndent(x, "", "  ")
	if err != nil {
		return "", fmt.Errorf("writing metadata: %w", err)
	}

	rendered := xml.Header + string(out) + "\n"

	back, err := parseMetadata(rendered)
	if err != nil || !proto.Equal(back, md) {
		return "", errUnwritableParts
	}

	return rendered, nil
}

func entityAttrsToXML(ed *samlv2.EntityDescriptor) *xmlEntityDescriptor {
	x := &xmlEntityDescriptor{EntityID: ed.GetEntityId(), ID: ed.GetId()}

	if ed.GetValidUntil() != nil {
		x.ValidUntil = ed.GetValidUntil().AsTime().UTC().Format(time.RFC3339Nano)
	}

	if ed.GetCacheDuration() != nil {
		x.CacheDuration = "PT" + strconv.FormatFloat(ed.GetCacheDuration().AsDuration().Seconds(), 'f', -1, 64) + "S"
	}

	return x
}

func idpToXML(d *samlv2.IDPSSODescriptor) *xmlIDPSSODescriptor {
	base := d.GetBase()

	x := &xmlIDPSSODescriptor{
		ProtocolSupportEnumeration: strings.Join(base.GetBase().GetProtocolSupportEnumeration(), " "),
		KeyDescriptor:              keysToXML(base.GetBase().GetKeyDescriptor()),
		SingleLogoutService:        endpointsToXML(base.GetSingleLogoutService()),
		NameIDFormat:               base.GetNameIdFormat(),
		SingleSignOnService:        endpointsToXML(d.GetSingleSignOnService()),
	}

	if d.GetWantAuthnRequestsSigned() {
		x.WantAuthnRequestsSigned = new(true)
	}

	return x
}

func spToXML(d *samlv2.SPSSODescriptor) *xmlSPSSODescriptor {
	base := d.GetBase()

	x := &xmlSPSSODescriptor{
		ProtocolSupportEnumeration: strings.Join(base.GetBase().GetProtocolSupportEnumeration(), " "),
		KeyDescriptor:              keysToXML(base.GetBase().GetKeyDescriptor()),
		SingleLogoutService:        endpointsToXML(base.GetSingleLogoutService()),
	}

	if d.GetAuthnRequestsSigned() {
		x.AuthnRequestsSigned = new(true)
	}

	if d.GetWantAssertionsSigned() {
		x.WantAssertionsSigned = new(true)
	}

	for _, acs := range d.GetAssertionConsumerService() {
		e := xmlIndexedEndpoint{xmlEndpoint: endpointToXML(acs.GetBase()), Index: int(acs.GetIndex())}
		if acs.GetIsDefault() {
			e.IsDefault = new(true)
		}

		x.AssertionConsumerService = append(x.AssertionConsumerService, e)
	}

	return x
}

func keysToXML(keys []*samlv2.KeyDescriptor) []xmlKeyDescriptor {
	uses := map[samlv2.KeyType]string{samlv2.KeyType_KEY_TYPE_SIGNING: "signing", samlv2.KeyType_KEY_TYPE_ENCRYPTION: "encryption"}

	out := make([]xmlKeyDescriptor, 0, len(keys))

	for _, k := range keys {
		var x xmlKeyDescriptor

		x.Use = uses[k.GetUse()]
		x.KeyInfo.X509Data.X509Certificate = string(k.GetKeyInfo().GetX509Certificate())
		out = append(out, x)
	}

	return out
}

func endpointsToXML(es []*samlv2.Endpoint) []xmlEndpoint {
	out := make([]xmlEndpoint, 0, len(es))
	for _, e := range es {
		out = append(out, endpointToXML(e))
	}

	return out
}

func endpointToXML(e *samlv2.Endpoint) xmlEndpoint {
	return xmlEndpoint{Binding: e.GetBinding(), Location: e.GetLocation(), ResponseLocation: e.GetResponseLocation()}
}

func organizationToXML(o *samlv2.Organization) *xmlOrganization {
	x := &xmlOrganization{}

	for _, n := range o.GetOrganizationName() {
		x.OrganizationName = append(x.OrganizationName, xmlLocalized{Lang: n.GetLang(), Value: n.GetValue()})
	}

	for _, n := range o.GetOrganizationDisplayName() {
		x.OrganizationDisplayName = append(x.OrganizationDisplayName, xmlLocalized{Lang: n.GetLang(), Value: n.GetValue()})
	}

	for _, u := range o.GetOrganizationUrl() {
		x.OrganizationURL = append(x.OrganizationURL, xmlLocalized{Lang: u.GetLang(), Value: u.GetValue()})
	}

	return x
}

func contactToXML(c *samlv2.ContactPerson) xmlContactPerson {
	x := xmlContactPerson{
		Company:         c.GetCompany(),
		GivenName:       c.GetGivenName(),
		SurName:         c.GetSurname(),
		EmailAddress:    c.GetEmailAddress(),
		TelephoneNumber: c.GetTelephoneNumber(),
	}

	for name, t := range contactTypes() {
		if t == c.GetContactType() {
			x.ContactType = name
		}
	}

	return x
}
