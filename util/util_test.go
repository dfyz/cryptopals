package util

import (
	"reflect"
	"testing"
)

func TestParseKV(t *testing.T) {
	goodTests := []struct {
		input    string
		expected map[string]string
	}{
		{"lol=kek", map[string]string{
			"lol": "kek",
		}},
		{"foo=bar&baz=qux&zap=zazzle", map[string]string{
			"foo": "bar",
			"baz": "qux",
			"zap": "zazzle",
		}},
		{"=&role==admin&user=", map[string]string{
			"":     "",
			"role": "=admin",
			"user": "",
		}},
	}
	for _, tt := range goodTests {
		actual, err := ParseKV(tt.input)
		if err != nil {
			t.Fatalf("Expected %v, got error %v", tt.expected, err)
		}
		if !reflect.DeepEqual(tt.expected, actual) {
			t.Fatalf("Expected %v, got %v", tt.expected, actual)
		}
	}

	badTests := []string{
		"&",
		"role=admin&&user=foo",
		"blah=&",
		"abc&def=ghi",
	}
	for _, tt := range badTests {
		actual, err := ParseKV(tt)
		if err == nil {
			t.Fatalf("Expected an error, got %v", actual)
		}
	}
}
