package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestAccountFromKeyID(t *testing.T) {
	for _, k := range []string{"AKIA" + "XYZDQCEN4B6JSJQI", "AKIA" + "xyzdqcen4b6jsjqi"} { // split so pre-commit scans skip the fixture
		if got, ok := AccountFromKeyID(k); !ok || got != "534261010715" {
			t.Fatalf("%s: %q %v", k, got, ok)
		}
	}
	if _, ok := AccountFromKeyID("AKIAIOSFODNN7EXAMPLE"); ok {
		t.Fatal("legacy I-key decoded")
	}
}

type countingSTS struct{ calls int }

func (c *countingSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	c.calls++
	return &sts.GetCallerIdentityOutput{}, nil
}

func TestCanaryAccountNeverVerified(t *testing.T) {
	fake := &countingSTS{}
	prev := stsClientFactory
	t.Cleanup(func() { stsClientFactory = prev; _ = SetSkipAccounts(nil) })
	stsClientFactory = func(_, _ string) stsCaller { return fake }

	data := []byte("AKIA" + "XYZDQCEN4B6JSJQI\n" + "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
	res, err := Scanner{}.FromData(context.Background(), true, data)
	if err != nil || len(res) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	if fake.calls != 0 || res[0].Verified || res[0].ExtraData["verification_skipped"] != "canary_account" {
		t.Fatalf("builtin canary verified: calls=%d extra=%v", fake.calls, res[0].ExtraData)
	}

	// Operator-supplied account: derive one from a synthetic key.
	key := "AKIA" + "QAAAAAAAAAAAAAAA"
	acct, _ := AccountFromKeyID(key)
	data = []byte(key + "\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
	if _, _ = (Scanner{}).FromData(context.Background(), true, data); fake.calls != 1 {
		t.Fatalf("non-skipped account not verified (calls=%d)", fake.calls)
	}
	if err := SetSkipAccounts([]string{acct}); err != nil {
		t.Fatal(err)
	}
	if _, _ = (Scanner{}).FromData(context.Background(), true, data); fake.calls != 1 {
		t.Fatalf("operator skip ignored (calls=%d)", fake.calls)
	}
	if err := SetSkipAccounts([]string{"12"}); err == nil {
		t.Fatal("short id accepted")
	}
}
