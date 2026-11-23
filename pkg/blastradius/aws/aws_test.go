package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func enc(s string) string { return url.QueryEscape(s) }

func resources(am *detectors.AccessMap, typ string) map[string][]string {
	out := map[string][]string{}
	for _, r := range am.Resources {
		if r.Type == typ {
			out[r.Name] = r.Permissions
		}
	}
	return out
}

func TestAssumedRolePolicyEvaluationAndTrustPaths(t *testing.T) {
	inline := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::data/*"},{"Effect":"Allow","Action":"sts:AssumeRole","Resource":["arn:aws:iam::111:role/deploy","arn:aws:iam::999:role/xacct"]},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`
	managed := `{"Statement":{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}}`
	trustDirect := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111:role/app"},"Action":"sts:AssumeRole"}]}`
	trustAccount := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111:root"},"Action":"sts:AssumeRole"}]}`
	trustOther := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
	var seen []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		a := r.Form.Get("Action")
		seen = append(seen, a)
		switch a {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`<X><GetCallerIdentityResult><Arn>arn:aws:sts::111:assumed-role/app/sess</Arn><Account>111</Account></GetCallerIdentityResult></X>`))
		case "GetAccessKeyLastUsed":
			_, _ = w.Write([]byte(`<X><GetAccessKeyLastUsedResult><AccessKeyLastUsed><LastUsedDate>2026-11-01T10:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>us-west-2</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></X>`))
		case "ListAttachedRolePolicies":
			if r.Form.Get("RoleName") != "app" {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`<X><R><AttachedPolicies><member><PolicyName>EC2Read</PolicyName><PolicyArn>arn:aws:iam::111:policy/EC2Read</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated></R></X>`))
		case "GetPolicy":
			_, _ = w.Write([]byte(`<X><GetPolicyResult><Policy><DefaultVersionId>v3</DefaultVersionId></Policy></GetPolicyResult></X>`))
		case "GetPolicyVersion":
			if r.Form.Get("VersionId") != "v3" {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`<X><GetPolicyVersionResult><PolicyVersion><Document>` + enc(managed) + `</Document></PolicyVersion></GetPolicyVersionResult></X>`))
		case "ListRolePolicies":
			_, _ = w.Write([]byte(`<X><R><PolicyNames><member>inline</member></PolicyNames></R></X>`))
		case "GetRolePolicy":
			_, _ = w.Write([]byte(`<X><GetRolePolicyResult><PolicyDocument>` + enc(inline) + `</PolicyDocument></GetRolePolicyResult></X>`))
		case "ListRoles":
			if r.Form.Get("Marker") == "" {
				_, _ = w.Write([]byte(`<X><R><Roles>
					<member><RoleName>deploy</RoleName><Arn>arn:aws:iam::111:role/deploy</Arn><AssumeRolePolicyDocument>` + enc(trustAccount) + `</AssumeRolePolicyDocument></member>
					<member><RoleName>admin</RoleName><Arn>arn:aws:iam::111:role/admin</Arn><AssumeRolePolicyDocument>` + enc(trustDirect) + `</AssumeRolePolicyDocument></member>
				</Roles><IsTruncated>true</IsTruncated><Marker>m2</Marker></R></X>`))
				return
			}
			_, _ = w.Write([]byte(`<X><R><Roles>
				<member><RoleName>ec2</RoleName><Arn>arn:aws:iam::111:role/ec2</Arn><AssumeRolePolicyDocument>` + enc(trustOther) + `</AssumeRolePolicyDocument></member>
				<member><RoleName>audit</RoleName><Arn>arn:aws:iam::111:role/audit</Arn><AssumeRolePolicyDocument>` + enc(trustAccount) + `</AssumeRolePolicyDocument></member>
			</Roles><IsTruncated>false</IsTruncated></R></X>`))
		default:
			w.WriteHeader(403)
		}
	}))
	defer s.Close()
	am, err := Mapper{STSURL: s.URL, IAMURL: s.URL}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "AKIA1", Secondary: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if am.Identity.Type != "assumed-role" || am.Activity == nil || am.Activity.LastUsed != "2026-11-01T10:00:00Z" || am.Activity.Service != "s3" {
		t.Fatalf("identity/activity %+v %+v", am.Identity, am.Activity)
	}
	for _, p := range []string{"policy:EC2Read", "policy:inline", "allow:s3:GetObject", "allow:ec2:Describe*", "allow:sts:AssumeRole", "deny:s3:DeleteObject"} {
		if !slices.Contains(am.Permissions, p) {
			t.Fatalf("missing %s in %v", p, am.Permissions)
		}
	}
	if got := resources(am, "aws_resource")["arn:aws:s3:::data/*"]; !slices.Equal(got, []string{"s3:GetObject", "s3:PutObject"}) {
		t.Fatalf("s3 resource %v", got)
	}
	roles := resources(am, "assumable_role")
	want := map[string]string{
		"arn:aws:iam::111:role/admin":  "trust:direct",
		"arn:aws:iam::111:role/deploy": "trust:account",
		"arn:aws:iam::999:role/xacct":  "identity-policy (trust unverified)",
	}
	if len(roles) != len(want) {
		t.Fatalf("assumable roles %v", roles)
	}
	for r, how := range want {
		if got := roles[r]; len(got) != 2 || got[1] != how {
			t.Fatalf("%s = %v, want %s", r, got, how)
		}
	}
	// sts:AssumeRole on specific ARNs only; not a wildcard escalation.
	if am.Privileged {
		t.Fatalf("unexpected privileged: %v", am.Permissions)
	}
	if !strings.Contains(strings.Join(am.Limitations, "|"), "policy conditions not evaluated") {
		t.Fatalf("limitations %v", am.Limitations)
	}
}

func TestEvaluationPrivilege(t *testing.T) {
	cases := map[string]bool{
		`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`:                                                                true,
		`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`:                                                     true,
		`{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`:          false,
		`{"Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`:                                                          false,
		`{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`:                                                         true,
		`{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:1:x"}]}`: false,
	}
	for doc, want := range cases {
		st, err := parsePolicy(doc)
		if err != nil {
			t.Fatal(err)
		}
		e := newEvaluation()
		e.add(st)
		if got := e.privileged(); got != want {
			t.Errorf("%s: privileged=%v want %v", doc, got, want)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		p, s string
		ok   bool
	}{
		{"s3:*", "s3:GetObject", true}, {"S3:get*", "s3:GetObject", true}, {"arn:aws:s3:::b/*", "arn:aws:s3:::b/k/deep", true},
		{"ec2:Describe?", "ec2:DescribeX", true}, {"iam:Get*", "iam:PassRole", false},
	} {
		if glob(c.p, c.s) != c.ok {
			t.Errorf("glob(%q,%q) != %v", c.p, c.s, c.ok)
		}
	}
}
