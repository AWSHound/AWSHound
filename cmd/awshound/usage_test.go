package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/AWSHound/AWSHound/internal/runtime"
)

func TestResolveCollectorsDefaultAndReplacement(t *testing.T) {
	if got := resolveCollectors(nil); !reflect.DeepEqual(got, runtime.DefaultCollectors) {
		t.Fatalf("resolveCollectors(nil) = %v, want %v", got, runtime.DefaultCollectors)
	}
	for _, svc := range runtime.DefaultCollectors {
		if svc == "s3" {
			t.Fatal("DefaultCollectors unexpectedly contains s3")
		}
	}

	var explicit stringSlice
	if err := explicit.Set("iam,s3"); err != nil {
		t.Fatal(err)
	}
	if got, want := resolveCollectors(explicit), []string{"iam", "s3"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveCollectors(iam,s3) = %v, want %v", got, want)
	}
}

func TestCollectionFlagUsagesDescribeActualDefaults(t *testing.T) {
	if strings.Contains(regionsFlagUsage, "default: us-east-1") {
		t.Errorf("regionsFlagUsage = %q; must not claim us-east-1 is the collection default", regionsFlagUsage)
	}
	if !strings.Contains(regionsFlagUsage, "auto-discover") {
		t.Errorf("regionsFlagUsage = %q; expected mention of enabled-region auto-discovery", regionsFlagUsage)
	}
	if !strings.Contains(collectorsFlagUsage, "replaces") {
		t.Errorf("collectorsFlagUsage = %q; expected mention that --collectors replaces the default list", collectorsFlagUsage)
	}
	for _, svc := range runtime.DefaultCollectors {
		if !strings.Contains(collectorsFlagUsage, svc) {
			t.Errorf("collectorsFlagUsage = %q; missing default collector %q", collectorsFlagUsage, svc)
		}
	}
}
