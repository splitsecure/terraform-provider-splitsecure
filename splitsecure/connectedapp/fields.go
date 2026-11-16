package connectedapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// ErrJSONValue is returned for a JSON object value a record cannot hold.
var ErrJSONValue = errors.New("invalid JSON object value")

// maxSafeJSONInt is the largest integer a JSON number holds exactly.
const maxSafeJSONInt = 1<<53 - 1

// Affix holds a text value to a prefix, a suffix and a byte length; zero
// parts are unconstrained.
type Affix struct {
	Prefix    string
	Suffix    string
	MaxLength uint32
}

// ModifiableStringOptions is what a sign-in may set a modifiable text to:
// one of Choices when set, else a value within Affix. Default, when set, is
// the value a sign-in that sets none gets.
type ModifiableStringOptions struct {
	Default *string
	Choices []string
	Affix   *Affix
}

// FixedString returns a text field the app fixes.
func FixedString(name, value string) *pb.Field {
	return stringField(name, &pb.StringField{Source: &pb.StringField_Fixed{Fixed: &pb.StringValue{Value: value}}})
}

// ModifiableString returns a text field each sign-in sets.
func ModifiableString(name string, opts ModifiableStringOptions) *pb.Field {
	m := &pb.StringModifiable{}
	if opts.Default != nil {
		m.DefaultValue = &pb.StringValue{Value: *opts.Default}
	}

	switch {
	case opts.Choices != nil:
		m.Constraint = &pb.StringModifiable_Choices{Choices: &pb.StringChoices{Values: opts.Choices}}
	case opts.Affix != nil:
		m.Constraint = &pb.StringModifiable_Affix{Affix: opts.Affix.proto()}
	default:
		m.Constraint = &pb.StringModifiable_Affix{Affix: &pb.StringAffix{}}
	}

	return stringField(name, &pb.StringField{Source: &pb.StringField_Modifiable{Modifiable: m}})
}

// DerivedString returns a text field derived from a proposal id, at creation
// or at each sign-in.
func DerivedString(name string, derived pb.Derived) *pb.Field {
	return stringField(name, &pb.StringField{Source: &pb.StringField_Derived{Derived: derived}})
}

// RequesterString returns a text field the backend fills from the
// requester, held to suffix when one is set.
func RequesterString(name string, kind pb.Requester, suffix string) *pb.Field {
	src := &pb.RequesterSource{Kind: kind}
	if suffix != "" {
		src.Constraint = &pb.StringAffix{Suffix: suffix}
	}

	return stringField(name, &pb.StringField{Source: &pb.StringField_Requester{Requester: src}})
}

// FixedStringList returns a list field the app fixes.
func FixedStringList(name string, values []string) *pb.Field {
	return stringListField(name, &pb.StringListField{
		Source: &pb.StringListField_Fixed{Fixed: &pb.StringListValue{Values: values}},
	})
}

// ModifiableStringList returns a list field each sign-in sets to a subset of
// choices, else to defaults when defaults is not nil.
func ModifiableStringList(name string, choices, defaults []string) *pb.Field {
	m := &pb.StringListModifiable{Choices: &pb.StringChoices{Values: choices}}
	if defaults != nil {
		m.DefaultValue = &pb.StringListValue{Values: defaults}
	}

	return stringListField(name, &pb.StringListField{Source: &pb.StringListField_Modifiable{Modifiable: m}})
}

// FixedDuration returns a duration field the app fixes, in seconds.
func FixedDuration(name string, seconds int64) *pb.Field {
	return durationField(name, &pb.DurationField{
		Source: &pb.DurationField_Fixed{Fixed: &pb.DurationValue{Value: duration(seconds)}},
	})
}

// DurationRange returns a duration field each sign-in chooses within min and
// max, else defaultSeconds when it is not nil. Seconds.
func DurationRange(name string, minSeconds, maxSeconds int64, defaultSeconds *int64) *pb.Field {
	m := &pb.DurationModifiable{Range: &pb.DurationRange{Min: duration(minSeconds), Max: duration(maxSeconds)}}
	if defaultSeconds != nil {
		m.DefaultValue = &pb.DurationValue{Value: duration(*defaultSeconds)}
	}

	return durationField(name, &pb.DurationField{Source: &pb.DurationField_Modifiable{Modifiable: m}})
}

// Member is one JSON object member. Value is a string, a bool, an int or
// int64, a float64 or json.Number holding an integer, a []any, a
// map[string]any or a []Member. Null is refused.
type Member struct {
	Name  string
	Value any
}

// FixedJSONObject returns a JSON object field the app fixes, members in order.
func FixedJSONObject(name string, members []Member) (*pb.Field, error) {
	obj, err := jsonObject(members)
	if err != nil {
		return nil, fmt.Errorf("field %s: %w", name, err)
	}

	return jsonObjectField(name, obj), nil
}

func (a *Affix) proto() *pb.StringAffix {
	return &pb.StringAffix{Prefix: a.Prefix, Suffix: a.Suffix, MaxLength: a.MaxLength}
}

func duration(seconds int64) *durationpb.Duration {
	return &durationpb.Duration{Seconds: seconds}
}

func stringField(name string, s *pb.StringField) *pb.Field {
	return &pb.Field{Name: name, Type: &pb.Field_StringField{StringField: s}}
}

func stringListField(name string, s *pb.StringListField) *pb.Field {
	return &pb.Field{Name: name, Type: &pb.Field_StringListField{StringListField: s}}
}

func durationField(name string, d *pb.DurationField) *pb.Field {
	return &pb.Field{Name: name, Type: &pb.Field_DurationField{DurationField: d}}
}

func jsonObjectField(name string, obj *pb.JsonObjectValue) *pb.Field {
	return &pb.Field{Name: name, Type: &pb.Field_JsonObjectField{
		JsonObjectField: &pb.JsonObjectField{Source: &pb.JsonObjectField_Fixed{Fixed: obj}},
	}}
}

func sortedMembers(obj map[string]any) []Member {
	out := make([]Member, 0, len(obj))
	for name, v := range obj {
		out = append(out, Member{Name: name, Value: v})
	}

	slices.SortFunc(out, func(a, b Member) int { return strings.Compare(a.Name, b.Name) })

	return out
}

func jsonObject(members []Member) (*pb.JsonObjectValue, error) {
	out := &pb.JsonObjectValue{Members: make([]*pb.JsonObjectValue_Member, 0, len(members))}

	for _, m := range members {
		v, err := jsonValue(m.Value)
		if err != nil {
			return nil, fmt.Errorf("member %q: %w", m.Name, err)
		}

		out.Members = append(out.Members, &pb.JsonObjectValue_Member{Name: m.Name, Value: v})
	}

	return out, nil
}

func jsonValue(v any) (*pb.JsonObjectValue_Value, error) {
	switch v := v.(type) {
	case string:
		return &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_StringValue{StringValue: v}}, nil
	case bool:
		return &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_BooleanValue{BooleanValue: v}}, nil
	case []Member:
		return objectValue(v)
	case map[string]any:
		return objectValue(sortedMembers(v))
	case []any:
		return listValue(v)
	case nil:
		return nil, fmt.Errorf("%w: null is not allowed", ErrJSONValue)
	}

	n, err := jsonInteger(v)
	if err != nil {
		return nil, err
	}

	return &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_IntegerValue{IntegerValue: n}}, nil
}

func objectValue(members []Member) (*pb.JsonObjectValue_Value, error) {
	obj, err := jsonObject(members)
	if err != nil {
		return nil, err
	}

	return &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_ObjectValue{ObjectValue: obj}}, nil
}

func listValue(items []any) (*pb.JsonObjectValue_Value, error) {
	list := &pb.JsonObjectValue_List{Values: make([]*pb.JsonObjectValue_Value, 0, len(items))}

	for i, item := range items {
		v, err := jsonValue(item)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}

		list.Values = append(list.Values, v)
	}

	return &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_ListValue{ListValue: list}}, nil
}

// jsonInteger returns v as an integer a JSON number holds exactly.
func jsonInteger(v any) (int64, error) {
	switch v := v.(type) {
	case int:
		return safeInteger(int64(v))
	case int64:
		return safeInteger(v)
	case float64:
		if v != math.Trunc(v) || math.Abs(v) > maxSafeJSONInt {
			return 0, fmt.Errorf("%w: number %v is not an integer within +-%d", ErrJSONValue, v, int64(maxSafeJSONInt))
		}

		return int64(v), nil
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, fmt.Errorf("%w: number %s is not an integer: %w", ErrJSONValue, v, err)
		}

		return safeInteger(n)
	}

	return 0, fmt.Errorf("%w: unsupported type %T", ErrJSONValue, v)
}

func safeInteger(n int64) (int64, error) {
	if n > maxSafeJSONInt || n < -maxSafeJSONInt {
		return 0, fmt.Errorf("%w: integer %d is outside +-%d", ErrJSONValue, n, int64(maxSafeJSONInt))
	}

	return n, nil
}
