package connectedapp

import (
	"encoding/json"
	"errors"
	"testing"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
)

func mustJSON(t *testing.T, name string, members []Member) *pb.Field {
	t.Helper()

	f, err := FixedJSONObject(name, members)
	if err != nil {
		t.Fatal(err)
	}

	return f
}

func str(s string) *pb.JsonObjectValue_Value {
	return &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_StringValue{StringValue: s}}
}

func integer(n int64) *pb.JsonObjectValue_Value {
	return &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_IntegerValue{IntegerValue: n}}
}

func TestFixedJSONObjectSortsMapMembersAndNests(t *testing.T) {
	got := mustJSON(t, "claims", []Member{{"obj", map[string]any{
		"tier":  float64(2),
		"team":  "platform",
		"on":    true,
		"zones": []any{"a", json.Number("3")},
		"meta":  map[string]any{"b": int64(1), "a": 1},
	}}})

	want := &pb.JsonObjectValue{Members: []*pb.JsonObjectValue_Member{
		{Name: "meta", Value: &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_ObjectValue{ObjectValue: &pb.JsonObjectValue{
			Members: []*pb.JsonObjectValue_Member{{Name: "a", Value: integer(1)}, {Name: "b", Value: integer(1)}},
		}}}},
		{Name: "on", Value: &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_BooleanValue{BooleanValue: true}}},
		{Name: "team", Value: str("platform")},
		{Name: "tier", Value: integer(2)},
		{Name: "zones", Value: &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_ListValue{ListValue: &pb.JsonObjectValue_List{
			Values: []*pb.JsonObjectValue_Value{str("a"), integer(3)},
		}}}},
	}}
	assertProtoEqual(t, got.GetJsonObjectField().GetFixed().GetMembers()[0].GetValue().GetObjectValue(), want)
}

func TestFixedJSONObjectKeepsMemberOrder(t *testing.T) {
	got := mustJSON(t, "claims", []Member{{"z", "last"}, {"a", maxSafeJSONInt}, {"m", -maxSafeJSONInt}})
	want := &pb.JsonObjectValue{Members: []*pb.JsonObjectValue_Member{
		{Name: "z", Value: str("last")},
		{Name: "a", Value: integer(maxSafeJSONInt)},
		{Name: "m", Value: integer(-maxSafeJSONInt)},
	}}
	assertProtoEqual(t, got.GetJsonObjectField().GetFixed(), want)
}

func TestFixedJSONObjectRefuses(t *testing.T) {
	tests := map[string]any{
		"null":                 nil,
		"fraction":             1.5,
		"float beyond 2^53":    float64(1 << 54),
		"integer beyond 2^53":  int64(maxSafeJSONInt + 1),
		"integer below -2^53":  -maxSafeJSONInt - 1,
		"json.Number fraction": json.Number("1.5"),
		"null in a list":       []any{"a", nil},
		"null in an object":    map[string]any{"a": nil},
		"unsupported type":     struct{}{},
	}

	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := FixedJSONObject("claims", []Member{{"v", value}})
			if !errors.Is(err, ErrJSONValue) {
				t.Errorf("error = %v, want ErrJSONValue", err)
			}
		})
	}
}

func TestModifiableStringConstraints(t *testing.T) {
	def := "b"
	tests := []struct {
		name string
		opts ModifiableStringOptions
		want *pb.StringModifiable
	}{
		{
			name: "choices with a default",
			opts: ModifiableStringOptions{Default: &def, Choices: []string{"a", "b"}},
			want: &pb.StringModifiable{
				DefaultValue: &pb.StringValue{Value: "b"},
				Constraint:   &pb.StringModifiable_Choices{Choices: &pb.StringChoices{Values: []string{"a", "b"}}},
			},
		},
		{
			name: "affix",
			opts: ModifiableStringOptions{Affix: &Affix{Prefix: "p-", MaxLength: 8}},
			want: &pb.StringModifiable{Constraint: &pb.StringModifiable_Affix{Affix: &pb.StringAffix{Prefix: "p-", MaxLength: 8}}},
		},
		{
			name: "neither is an empty affix",
			want: &pb.StringModifiable{Constraint: &pb.StringModifiable_Affix{Affix: &pb.StringAffix{}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertProtoEqual(t, ModifiableString("f", tt.opts).GetStringField().GetModifiable(), tt.want)
		})
	}
}

func TestModifiableStringListDefaults(t *testing.T) {
	without := ModifiableStringList("f", []string{"a"}, nil).GetStringListField().GetModifiable()
	if without.GetDefaultValue() != nil {
		t.Error("nil defaults set a default value")
	}

	with := ModifiableStringList("f", []string{"a", "b"}, []string{"b"}).GetStringListField().GetModifiable()
	assertProtoEqual(t, with, &pb.StringListModifiable{
		Choices:      &pb.StringChoices{Values: []string{"a", "b"}},
		DefaultValue: &pb.StringListValue{Values: []string{"b"}},
	})
}
