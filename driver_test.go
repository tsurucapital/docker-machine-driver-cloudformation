package main

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/service/cloudformation"
)

// TestParseTag that valid tag can be parsed.
func TestParseTag(t *testing.T) {
	key := "foo"
	val := "bar,baz"

	r, err := ParseTag(fmt.Sprintf("Key=%s,Value=%s", key, val))
	if err != nil {
		t.Errorf("Expected no error but got %s", err)
		return
	}
	if r == nil {
		t.Errorf("Parsed tag was nil")
		return
	}
	expected := cloudformation.Tag{
		Key:   &key,
		Value: &val,
	}

	if *r.Key != *expected.Key {
		t.Errorf("Expected key %s but got key %s", *r.Key, *expected.Key)
		return
	}

	if *r.Value != *expected.Value {
		t.Errorf("Expected value %s but got value %s", *r.Value, *expected.Value)
	}

}
