package connectedapp

import (
	"fmt"
	"slices"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// check refuses a field whose type, source or value the spec does not allow.
func (s *FieldSpec) check(f *pb.Field) error {
	typ, source := typeAndSource(f)

	if typ != s.Type {
		return fmt.Errorf("%w: field %s is %q, want %q", ErrFieldType, s.Name, typ, s.Type)
	}

	if !slices.Contains(s.Sources, source) {
		return fmt.Errorf("%w: field %s takes no %q source, only %v", ErrSource, s.Name, source, s.Sources)
	}

	if kind := f.GetStringField().GetRequester().GetKind(); source == SourceRequester && !slices.Contains(s.Requesters, kind.String()) {
		return fmt.Errorf("%w: field %s takes no %s requester, only %v", ErrSource, s.Name, kind, s.Requesters)
	}

	return s.checkValue(f)
}

// typeAndSource returns the arms of f's type and source oneofs; a missing arm,
// or one no create may hold, reads as empty.
func typeAndSource(f *pb.Field) (FieldType, Source) {
	switch t := f.GetType().(type) {
	case *pb.Field_StringField:
		return TypeString, stringSource(t.StringField)
	case *pb.Field_StringListField:
		switch t.StringListField.GetSource().(type) {
		case *pb.StringListField_Fixed:
			return TypeStringList, SourceFixed
		case *pb.StringListField_Modifiable:
			return TypeStringList, SourceModifiable
		}

		return TypeStringList, ""
	case *pb.Field_DurationField:
		switch t.DurationField.GetSource().(type) {
		case *pb.DurationField_Fixed:
			return TypeDuration, SourceFixed
		case *pb.DurationField_Modifiable:
			return TypeDuration, SourceModifiable
		}

		return TypeDuration, ""
	case *pb.Field_JsonObjectField:
		if t.JsonObjectField.GetFixed() != nil {
			return TypeJSONObject, SourceFixed
		}

		return TypeJSONObject, ""
	}

	return "", ""
}

func stringSource(s *pb.StringField) Source {
	switch src := s.GetSource().(type) {
	case *pb.StringField_Fixed:
		return SourceFixed
	case *pb.StringField_Modifiable:
		return SourceModifiable
	case *pb.StringField_Requester:
		return SourceRequester
	case *pb.StringField_Derived:
		switch src.Derived {
		case pb.Derived_DERIVED_PER_SIGN_IN_ID:
			return SourceDerivedPerSignIn
		case pb.Derived_DERIVED_AT_CREATION_ID:
			return SourceDerivedAtCreation
		case pb.Derived_DERIVED_UNSPECIFIED:
		}
	}

	return ""
}

// checkValue holds a fixed text to the spec's choices and a duration to its
// bounds.
func (s *FieldSpec) checkValue(f *pb.Field) error {
	if fixed := f.GetStringField().GetFixed(); fixed != nil && len(s.Choices) > 0 && !slices.Contains(s.Choices, fixed.GetValue()) {
		return fmt.Errorf("%w: field %s is %q, not one of %v", ErrValue, s.Name, fixed.GetValue(), s.Choices)
	}

	d := f.GetDurationField()
	if d == nil {
		return nil
	}

	for _, v := range []*durationpb.Duration{
		d.GetFixed().GetValue(),
		d.GetModifiable().GetRange().GetMin(),
		d.GetModifiable().GetRange().GetMax(),
		d.GetModifiable().GetDefaultValue().GetValue(),
	} {
		err := s.checkSeconds(v)
		if err != nil {
			return err
		}
	}

	r := d.GetModifiable().GetRange()
	if r.GetMin().GetSeconds() > r.GetMax().GetSeconds() {
		return fmt.Errorf("%w: field %s has a minimum above its maximum", ErrValue, s.Name)
	}

	return nil
}

func (s *FieldSpec) checkSeconds(v *durationpb.Duration) error {
	if v == nil {
		return nil
	}

	secs := v.GetSeconds()
	if (s.MinSeconds > 0 && secs < s.MinSeconds) || (s.MaxSeconds > 0 && secs > s.MaxSeconds) {
		return fmt.Errorf("%w: field %s is %ds, outside %d to %d seconds", ErrValue, s.Name, secs, s.MinSeconds, s.MaxSeconds)
	}

	return nil
}
