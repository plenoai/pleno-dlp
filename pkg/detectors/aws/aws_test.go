package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func TestFromData_Positive(t *testing.T) {
	data := []byte(`
aws_access_key_id     = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`)
	res, err := Scanner{}.FromData(context.Background(), false, data)
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if string(res[0].Raw) != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Raw = %s", res[0].Raw)
	}
	if len(res[0].RawV2) == 0 {
		t.Errorf("expected RawV2 to be populated with paired secret")
	}
	if res[0].Redacted != "AKIA..." {
		t.Errorf("Redacted = %q", res[0].Redacted)
	}
}

func TestFromData_Negative(t *testing.T) {
	data := []byte("nothing of interest here, just text without an aws key id")
	res, err := Scanner{}.FromData(context.Background(), false, data)
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res))
	}
}

func TestKeywords(t *testing.T) {
	kws := Scanner{}.Keywords()
	if len(kws) == 0 {
		t.Fatal("Keywords must not be empty")
	}
	if kws[0] != "AKIA" {
		t.Errorf("expected AKIA prefix keyword, got %v", kws)
	}
}

func TestSplitPair(t *testing.T) {
	id, sk, ok := splitPair("AKIAEXAMPLE:secretpart")
	if !ok || id != "AKIAEXAMPLE" || sk != "secretpart" {
		t.Errorf("splitPair = %q %q %v", id, sk, ok)
	}
	if _, _, ok := splitPair("nopairhere"); ok {
		t.Error("splitPair should fail without colon")
	}
}

// fakeSTS lets tests inject a deterministic GetCallerIdentity response
// without spinning an httptest server. The aws-sdk-go-v2 client takes
// dozens of options to point at a custom URL; the factory swap below is
// the smallest seam.
type fakeSTS struct {
	out *sts.GetCallerIdentityOutput
	err error
}

func (f *fakeSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return f.out, f.err
}

func withFakeSTS(t *testing.T, account, arn, userID string) {
	t.Helper()
	prev := stsClientFactory
	t.Cleanup(func() { stsClientFactory = prev })
	stsClientFactory = func(_, _ string) stsCaller {
		return &fakeSTS{out: &sts.GetCallerIdentityOutput{
			Account: ptr(account),
			Arn:     ptr(arn),
			UserId:  ptr(userID),
		}}
	}
}

func ptr(s string) *string { return &s }

func TestFromData_VerifyEnrichesIdentity(t *testing.T) {
	withFakeSTS(t, "123456789012", "arn:aws:iam::123456789012:user/Alice", "AIDAEXAMPLEUSERID")
	data := []byte("AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
	res, err := Scanner{}.FromData(context.Background(), true, data)
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if !res[0].Verified {
		t.Errorf("expected Verified=true")
	}
	if res[0].ExtraData["aws_account_id"] != "123456789012" {
		t.Errorf("aws_account_id = %q", res[0].ExtraData["aws_account_id"])
	}
	if res[0].ExtraData["aws_principal_kind"] != "user" {
		t.Errorf("aws_principal_kind = %q", res[0].ExtraData["aws_principal_kind"])
	}
	if res[0].ExtraData["aws_partition"] != "aws" {
		t.Errorf("aws_partition = %q", res[0].ExtraData["aws_partition"])
	}
	if _, privileged := res[0].ExtraData["aws_privileged"]; privileged {
		t.Errorf("non-admin user should not be flagged privileged")
	}
}

func TestFromData_RootIsPrivileged(t *testing.T) {
	withFakeSTS(t, "123456789012", "arn:aws:iam::123456789012:root", "123456789012")
	res, _ := Scanner{}.FromData(context.Background(), true,
		[]byte("AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"))
	if res[0].ExtraData["aws_principal_kind"] != "root" {
		t.Errorf("expected root, got %q", res[0].ExtraData["aws_principal_kind"])
	}
	if res[0].ExtraData["aws_privileged"] != "true" {
		t.Errorf("root must be privileged")
	}
}

func TestFromData_AdminRoleIsPrivileged(t *testing.T) {
	withFakeSTS(t, "555555555555",
		"arn:aws:sts::555555555555:assumed-role/AdminRole/session-id",
		"AROAEXAMPLE:session-id")
	res, _ := Scanner{}.FromData(context.Background(), true,
		[]byte("AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"))
	if res[0].ExtraData["aws_principal_kind"] != "assumed-role" {
		t.Errorf("kind = %q, want assumed-role", res[0].ExtraData["aws_principal_kind"])
	}
	if res[0].ExtraData["aws_privileged"] != "true" {
		t.Errorf("AdminRole must be privileged")
	}
}

func TestFromData_VerifyFailureNoMeta(t *testing.T) {
	prev := stsClientFactory
	t.Cleanup(func() { stsClientFactory = prev })
	stsClientFactory = func(_, _ string) stsCaller {
		return &fakeSTS{err: context.Canceled}
	}
	res, _ := Scanner{}.FromData(context.Background(), true,
		[]byte("AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"))
	if res[0].Verified {
		t.Errorf("expected Verified=false on STS error")
	}
	if _, ok := res[0].ExtraData["aws_account_id"]; ok {
		t.Errorf("metadata must be absent on STS failure")
	}
}

func TestParseARN(t *testing.T) {
	cases := []struct {
		arn      string
		wantPart string
		wantKind string
		wantOK   bool
	}{
		{"arn:aws:iam::123456789012:user/Alice", "aws", "user", true},
		{"arn:aws:iam::123456789012:root", "aws", "root", true},
		{"arn:aws:sts::123:assumed-role/Foo/bar", "aws", "assumed-role", true},
		{"arn:aws-cn:iam::1:user/x", "aws-cn", "user", true},
		{"arn:aws-us-gov:iam::1:role/Y", "aws-us-gov", "role", true},
		{"arn:aws:iam::1:federated-user/Bob", "aws", "federated-user", true},
		{"not-an-arn", "", "", false},
	}
	for _, c := range cases {
		part, kind, _, ok := parseARN(c.arn)
		if ok != c.wantOK || part != c.wantPart || kind != c.wantKind {
			t.Errorf("parseARN(%q) = (%q,%q,_,%v); want (%q,%q,_,%v)",
				c.arn, part, kind, ok, c.wantPart, c.wantKind, c.wantOK)
		}
	}
}

func TestIsPrivilegedResource(t *testing.T) {
	cases := []struct {
		kind, resource string
		want           bool
	}{
		{"root", "root", true},
		{"user", "user/Admin", true},
		{"user", "user/Alice", false},
		{"assumed-role", "assumed-role/Administrator/sess", true},
		{"assumed-role", "assumed-role/AWSReservedSSO_AdminAccess_xxx/sess", true},
		{"assumed-role", "assumed-role/OrganizationAccountAccessRole/sess", true},
		{"assumed-role", "assumed-role/ReadOnly/sess", false},
		{"role", "role/break-glass", true},
	}
	for _, c := range cases {
		if got := isPrivilegedResource(c.kind, c.resource); got != c.want {
			t.Errorf("isPrivilegedResource(%q,%q) = %v, want %v", c.kind, c.resource, got, c.want)
		}
	}
}
