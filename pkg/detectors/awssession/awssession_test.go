package awssession

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const dummyID = "ASIAQWERTYUIOPASDFGH"
const dummySecret = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
const dummySession = "FwoGZXIvYXdzECAaDF1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij"

func tripleBody() []byte {
	// A space after the `=` gives the session-token regex a clean leading
	// boundary; otherwise `_TOKEN=` (all base64-class chars) merges into the
	// capture. Real env exports often quote or space-separate the value.
	return []byte("AWS_ACCESS_KEY_ID=" + dummyID + "\n" +
		"AWS_SECRET_ACCESS_KEY=" + dummySecret + "\n" +
		"AWS_SESSION_TOKEN= " + dummySession + " \n")
}

func TestFromData_TripleNearKeyword(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, tripleBody())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("Raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Verified {
		t.Fatal("verify=false must not set Verified=true")
	}
	if res[0].ExtraData["access_key_id"] != dummyID {
		t.Fatalf("extra access_key_id mismatch")
	}
}

func TestFromData_NoSessionContext(t *testing.T) {
	// Bare ASIA without any session_token co-occurrence and no keyword
	// nearby — must not fire. ASIA shows up in IAM policy fixtures.
	body := []byte("Resource: arn:aws:iam::000000000000:role/foo " + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ASIAQWER") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestSplitTriple(t *testing.T) {
	id, sk, session, ok := splitTriple("ASIAID:secretpart:FwoGtoken+/=")
	if !ok || id != "ASIAID" || sk != "secretpart" || session != "FwoGtoken+/=" {
		t.Errorf("splitTriple = %q %q %q %v", id, sk, session, ok)
	}
	if _, _, _, ok := splitTriple("only:two"); ok {
		t.Error("splitTriple should fail without two colons")
	}
	if _, _, _, ok := splitTriple("noseparators"); ok {
		t.Error("splitTriple should fail without a colon")
	}
}

// fakeSTS injects a deterministic GetCallerIdentity response without
// signing/HTTP, mirroring the sibling aws detector's seam.
type fakeSTS struct {
	out *sts.GetCallerIdentityOutput
	err error
}

func (f *fakeSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return f.out, f.err
}

func swapFactory(t *testing.T, mk func(id, secret, session string) stsCaller) {
	t.Helper()
	prev := stsClientFactory
	t.Cleanup(func() { stsClientFactory = prev })
	stsClientFactory = mk
}

func ptr(s string) *string { return &s }

// 200 with a valid identity -> Verified=true, metadata enriched, and the full
// session token (not the redacted prefix) is threaded into the verify call.
func TestFromData_VerifyAccept(t *testing.T) {
	var sawSession string
	swapFactory(t, func(_, _, session string) stsCaller {
		sawSession = session
		return &fakeSTS{out: &sts.GetCallerIdentityOutput{
			Account: ptr("123456789012"),
			Arn:     ptr("arn:aws:sts::123456789012:assumed-role/Foo/sess"),
			UserId:  ptr("AROAEXAMPLE:sess"),
		}}
	})
	res, err := Scanner{}.FromData(context.Background(), true, tripleBody())
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true on accept")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("unexpected VerificationErr: %v", res[0].VerificationErr)
	}
	if res[0].ExtraData["aws_account_id"] != "123456789012" {
		t.Errorf("aws_account_id = %q", res[0].ExtraData["aws_account_id"])
	}
	if sawSession != dummySession {
		t.Errorf("verify must receive the full session token, got %q", sawSession)
	}
}

// Credential rejection (HTTP 403: InvalidClientTokenId / ExpiredToken) ->
// clean Verified=false with no VerificationErr.
func TestFromData_VerifyReject(t *testing.T) {
	for _, code := range []string{"InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken"} {
		swapFactory(t, func(_, _, _ string) stsCaller {
			return &fakeSTS{err: errors.New("operation error STS: GetCallerIdentity, https response error StatusCode: 403, api error " + code + ": The security token included in the request is invalid.")}
		})
		res, _ := Scanner{}.FromData(context.Background(), true, tripleBody())
		if res[0].Verified {
			t.Errorf("%s: expected Verified=false", code)
		}
		if res[0].VerificationErr != nil {
			t.Errorf("%s: rejection must not surface VerificationErr, got %v", code, res[0].VerificationErr)
		}
		if _, ok := res[0].ExtraData["aws_account_id"]; ok {
			t.Errorf("%s: metadata must be absent on rejection", code)
		}
	}
}

// Rate limit (429) and transport errors -> Verified=false WITH a
// VerificationErr; no retry.
func TestFromData_VerifyTransient(t *testing.T) {
	cases := map[string]error{
		"throttle":  errors.New("operation error STS: GetCallerIdentity, https response error StatusCode: 429, api error Throttling: Rate exceeded"),
		"500":       errors.New("operation error STS: GetCallerIdentity, https response error StatusCode: 500, api error InternalFailure"),
		"transport": context.DeadlineExceeded,
	}
	for name, e := range cases {
		swapFactory(t, func(_, _, _ string) stsCaller {
			return &fakeSTS{err: e}
		})
		res, _ := Scanner{}.FromData(context.Background(), true, tripleBody())
		if res[0].Verified {
			t.Errorf("%s: expected Verified=false", name)
		}
		if res[0].VerificationErr == nil {
			t.Errorf("%s: transient failure must surface VerificationErr", name)
		}
	}
}

func TestKeywords(t *testing.T) {
	if len(Scanner{}.Keywords()) == 0 {
		t.Fatal("Keywords must not be empty")
	}
}
