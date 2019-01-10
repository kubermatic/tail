package handler

import (
	"fmt"
	"regexp"
	"testing"
)

func TestPathCheckerRegex(t *testing.T) {
	tests := []struct {
		path    string
		allowed bool
	}{
		{
			path:    "build/bucket/pr-logs/pull/org_repo/2548/pull-with_underscore_and./1079687257834655744",
			allowed: true,
		},
		{
			path:    "wrong-prefix/bucket/pr-logs/pull/org_repo/2548/pull-with_underscore_and./1079687257834655744",
			allowed: false,
		},
		{
			path:    "build/bucket/pr-logs/pull/org_repo/2548/pull-without-id",
			allowed: false,
		},
		{
			path:    "build/my-repo/pr-logs/pull/org_repo/no-pr-number/pull-with_underscore_and./1079687257834655744",
			allowed: false,
		},
		{
			path:    "build/bucket/pr-logs/pull/org_repo-abc1234/567/pull-with_underscore_and./1079687257834655744",
			allowed: true,
		},
	}
	pathChecker, err := regexp.Compile(fmt.Sprintf(pathCheckerRegexpTemplate, "bucket"))
	if err != nil {
		t.Fatalf("failed to compile regexp: %v", err)
	}

	for _, test := range tests {
		matches := pathChecker.MatchString(test.path)
		if matches != test.allowed {
			t.Errorf("expected pathChecker regex to match string '%s': %t but was %t", test.path, test.allowed, matches)
		}
	}

}
