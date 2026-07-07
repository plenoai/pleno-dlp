//go:build detector_unit

package generic

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestFromData_FiresNearKeyword(t *testing.T) {
	chunk := []byte(`config:
  database_url: postgres://localhost
  api_key = "Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"
`)
	res, err := Scanner{}.FromData(context.Background(), false, chunk)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected at least one finding")
	}
	if res[0].DetectorType != detectors.GenericHighEntropy {
		t.Errorf("wrong type: %v", res[0].DetectorType)
	}
	if !strings.Contains(string(res[0].Raw), "Hf83KdjL9qZ8") {
		t.Errorf("captured wrong span: %q", res[0].Raw)
	}
}

func TestFromData_RejectsLowEntropy(t *testing.T) {
	chunk := []byte(`api_key=000000000000000000000000000000000000000000000000000000000000`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 0 {
		t.Fatalf("expected zero hits on all-zeros, got %d (raw=%q)", len(res), res[0].Raw)
	}
}

func TestFromData_RejectsHighEntropyWithoutKeyword(t *testing.T) {
	chunk := []byte(`commit abc123def456ghi789jkl012mno345pqr678stu901vwx234yz5
files: 42
`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 0 {
		t.Fatalf("expected zero hits without keyword, got %d", len(res))
	}
}

func TestFromData_RejectsKeywordTooFar(t *testing.T) {
	prefix := "api_key=safe-public-value\n"
	gap := strings.Repeat("a non-secret line of plain text\n", 12) // ~360 bytes
	suffix := `  hidden = "Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"`
	chunk := []byte(prefix + gap + suffix)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(string(r.Raw), "Hf83KdjL9qZ8") {
			t.Errorf("entropy run far from keyword must NOT match; got %q", r.Raw)
		}
	}
}

func TestFromData_DedupsSameSecret(t *testing.T) {
	// Engine dedup is a separate layer keyed on location too — here we
	// just confirm we don't double-emit from one chunk.
	secret := "Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"
	chunk := []byte("api_key=" + secret + "\nfallback_token=" + secret)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact_StableShape(t *testing.T) {
	got := redact("Hf83KdjL9qZ8xVnB2Wm7TpRc")
	if got != "Hf83..." {
		t.Errorf("redact: %q", got)
	}
	if redact("abc") != "abc" {
		t.Error("short strings shouldn't be ellipsised")
	}
}

func TestKeywords_NotEmpty(t *testing.T) {
	kws := Scanner{}.Keywords()
	if len(kws) < 5 {
		t.Fatalf("expected substantial keyword list, got %d", len(kws))
	}
	// Every keyword must already be lowercase — engine matches case-
	// insensitively but we promise to ship lowercase.
	for _, kw := range kws {
		if kw != strings.ToLower(kw) {
			t.Errorf("keyword %q must be lowercase", kw)
		}
	}
}

func TestFromData_RejectsCamelCaseIdentifier(t *testing.T) {
	// Entropy ≥ 4.0 but it's source code, not a secret; real example from
	// aws-sdk-go-v2/aws/credentials.go.
	chunk := []byte(`// CredentialsCache provides caching for credentials.
type CredentialsCache struct {
	provider CredentialsProvider
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(string(r.Raw), "Credentials") {
			t.Errorf("CamelCase identifier must NOT match; got %q", r.Raw)
		}
	}
}

func TestFromData_RejectsImportPath(t *testing.T) {
	chunk := []byte(`// credential helpers from "github.com/aws/aws-sdk-go-v2/aws/credentials"`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(string(r.Raw), "com/aws") {
			t.Errorf("import path must NOT match; got %q", r.Raw)
		}
	}
}

func TestLooksLikeIdentifier(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"CredentialProviderOptions", true},      // CamelCase Go ident
		{"UserAgentFeatureResourceModel", true},  // CamelCase Go ident
		{"TestSign_buildCanonicalHeaders", true}, // Go test ident with underscore
		{"AKIAIOSFODNN7EXAMPLE", false},          // AWS-style access key (has digit)
		{"Hf83KdjL9qZ8xVnB2Wm7TpRc", false},      // mixed case + digits → real-shaped
		{"ghp_aBcDeF123XYZ", false},              // has digits → real-shaped
		{"abc/def/ghi/jkl/mno", false},           // has `/`, disqualifies identifier
	}
	for _, c := range cases {
		if got := looksLikeIdentifier(c.s); got != c.want {
			t.Errorf("looksLikeIdentifier(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestLooksLikePath(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"com/aws/aws-sdk-go-v2", true},
		{"a/b/c", true},
		{"a/b", false}, // single slash — could be base64
		{"Hf83KdjL9qZ8xVnB2Wm7TpRc", false},
		{"path/with/slashes/here", true},
	}
	for _, c := range cases {
		if got := looksLikePath(c.s); got != c.want {
			t.Errorf("looksLikePath(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestLooksLikeSRIHash(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"sha256-RFWPLDbv2BY+rCkDzsE+0fr8ylQr2a", true},
		{"sha384-H8BRh8j48O9oYatfu5AZzq9to9wNipiB", true},
		{"sha512-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K", true},
		{"SHA256-uppercaseprefix", true},
		{"Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01", false},
		{"AKIAIOSFODNN7EXAMPLE0000000000000", false},
	}
	for _, c := range cases {
		if got := looksLikeSRIHash(c.s); got != c.want {
			t.Errorf("looksLikeSRIHash(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestLooksLikeHexDigest(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", true},                                 // MD5 (32)
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", true},                         // SHA-1 (40)
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true}, // SHA-256 (64)
		{"Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01", false},                  // non-hex chars
		{"a1b2c3d4e5f6a1b2c3d4", false},                                            // 20 chars, not a standard digest length
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1", false},  // 63 chars, not standard
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5", false},                              // 35 chars
		{"DEADBEEFDEADBEEFDEADBEEFDEADBEEF", true},                                 // uppercase hex, MD5 length
	}
	for _, c := range cases {
		if got := looksLikeHexDigest(c.s); got != c.want {
			t.Errorf("looksLikeHexDigest(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestFromData_RejectsSRIHash(t *testing.T) {
	// npm package-lock.json integrity field: should not fire even though
	// "integrity" is near "password" from an unrelated section.
	chunk := []byte(`{
  "password": "exampleSensitiveNear",
  "integrity": "sha512-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/eO0EQ3HjgL1WxQvGKYfh8hqQRk="
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		raw := string(r.Raw)
		if strings.HasPrefix(strings.ToLower(raw), "sha") {
			t.Errorf("SRI hash must NOT fire; got %q", raw)
		}
	}
}

func TestFromData_RejectsHexDigestInLockfile(t *testing.T) {
	chunk := []byte(`{
  "auth": "token",
  "hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if string(r.Raw) == "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
			t.Errorf("hex digest in hash context must NOT fire; got %q", r.Raw)
		}
	}
}

func TestFromData_StillFiresOnRealSecret(t *testing.T) {
	// A real-looking API key near a keyword must still be detected even when
	// an SRI hash appears elsewhere in the chunk.
	chunk := []byte(`{
  "integrity": "sha256-abc123",
  "api_key": "Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	found := false
	for _, r := range res {
		if strings.Contains(string(r.Raw), "Hf83KdjL9qZ8") {
			found = true
		}
	}
	if !found {
		t.Error("real API key must still fire even when SRI hash is in the same chunk")
	}
}

func TestShannonEntropy_CalibratesAtFour(t *testing.T) {
	if e := shannonEntropy("Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"); e < 4.0 {
		t.Errorf("random b64 must score >= 4.0, got %v", e)
	}
	if e := shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); e > 1.0 {
		t.Errorf("all-same-char must score < 1.0, got %v", e)
	}
}

// --- #249: hash-dense PHP/JS context gating -------------------------------
//
// The fixtures below are lifted (shape-for-shape, not byte-for-byte) from
// what actually fired on laravel/framework and axios/axios during the
// issue #249 repro. Each "Rejects" test is a measured false-positive
// class; TestFromData_StillFiresOnLaravelAppKeyShapedSecret and
// TestFromData_StillFiresOnRealSecret (above) are the recall controls —
// real-format-looking secrets in the same kind of file that MUST keep
// firing.

func TestLooksLikeCryptHashFragment(t *testing.T) {
	// bcrypt: $2y$13$<22-char-salt><31-char-hash>, split by `.` into two
	// secretShape runs the way laravel/framework's
	// EloquentModelHashedCastingTest.php does.
	bcrypt := []byte(`'password' => '$2y$13$Hdxlvi7OZqK3/fKVNypJs.vJqQcmOo3HnnT6w7fec9FRTRYxAhuCO',`)
	salt := "Hdxlvi7OZqK3/fKVNypJs"
	saltStart := bytes.Index(bcrypt, []byte(salt))
	if !looksLikeCryptHashFragment(bcrypt, saltStart, saltStart+len(salt)) {
		t.Error("bcrypt salt segment must be recognized as a crypt-hash fragment")
	}
	hash := "vJqQcmOo3HnnT6w7fec9FRTRYxAhuCO"
	hashStart := bytes.Index(bcrypt, []byte(hash))
	if !looksLikeCryptHashFragment(bcrypt, hashStart, hashStart+len(hash)) {
		t.Error("bcrypt hash segment must be recognized as a crypt-hash fragment")
	}

	// argon2i: $argon2i$v=19$m=...$<salt>$<hash>
	argon := []byte(`'password' => '$argon2i$v=19$m=1024,t=2,p=2$OENON0I5bXo2WDQyQnM2bg$3ma8cKHITsmAjyIYKDLdSvtkMCiEz/s6qWnLAf+Ehek',`)
	argonHash := "3ma8cKHITsmAjyIYKDLdSvtkMCiEz/s6qWnLAf+Ehek"
	argonStart := bytes.Index(argon, []byte(argonHash))
	if !looksLikeCryptHashFragment(argon, argonStart, argonStart+len(argonHash)) {
		t.Error("argon2i hash segment must be recognized as a crypt-hash fragment")
	}

	// Not a hash: real secret near a keyword, no `$` markers anywhere.
	real := []byte(`api_key = "Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"`)
	realStart := bytes.Index(real, []byte("Hf83"))
	if looksLikeCryptHashFragment(real, realStart, realStart+46) {
		t.Error("real secret must NOT be recognized as a crypt-hash fragment")
	}
}

func TestFromData_RejectsBcryptHashFragment(t *testing.T) {
	// Real shape from laravel/framework's EloquentModelHashedCastingTest.php.
	chunk := []byte(`
        HashedCast::create([
            'password' => '$2y$13$Hdxlvi7OZqK3/fKVNypJs.vJqQcmOo3HnnT6w7fec9FRTRYxAhuCO',
        ]);
`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 0 {
		t.Errorf("bcrypt hash literal near 'password' must NOT fire, got %d: %v", len(res), res)
	}
}

func TestFromData_RejectsArgon2HashFragment(t *testing.T) {
	chunk := []byte(`
        HashedCast::create([
            'password' => '$argon2i$v=19$m=1024,t=2,p=2$OENON0I5bXo2WDQyQnM2bg$3ma8cKHITsmAjyIYKDLdSvtkMCiEz/s6qWnLAf+Ehek',
        ]);
`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 0 {
		t.Errorf("argon2i hash literal near 'password' must NOT fire, got %d: %v", len(res), res)
	}
}

func TestLooksLikeIdentifierWithAlgoName(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"testBasicArgon2iHashing", true},
		{"testBasicArgon2idHashing", true},
		{"testBasicArgon2idVerification", true},
		{"Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01", false}, // no algo token: untouched
		{"AKIAIOSFODNN7EXAMPLE", false},                           // no algo token: untouched
		{"ghp_aBcDeF123XYZ", false},                               // no algo token: untouched
	}
	for _, c := range cases {
		if got := looksLikeIdentifierWithAlgoName(c.s); got != c.want {
			t.Errorf("looksLikeIdentifierWithAlgoName(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestFromData_RejectsAlgoNameTestIdentifier(t *testing.T) {
	// Real shape from laravel/framework's tests/Hashing/HasherTest.php.
	chunk := []byte(`
    #[Depends('testBasicArgon2idHashing')]
    public function testBasicArgon2idVerification()
    {
        $this->assertTrue(password_verify('password', $subject->password));
    }
`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(strings.ToLower(string(r.Raw)), "argon") {
			t.Errorf("camelCase test-method identifier must NOT fire; got %q", r.Raw)
		}
	}
}

func TestLooksLikeBundlerAssetFilename(t *testing.T) {
	data := []byte(`"file": "assets/AuthenticatedLayout-DfWF52N1.js",`)
	secret := "assets/AuthenticatedLayout-DfWF52N1"
	end := bytes.Index(data, []byte(secret)) + len(secret)
	if !looksLikeBundlerAssetFilename(secret, data, end) {
		t.Error("Vite-style content-hash filename must be recognized as a bundler asset")
	}
	// No hyphen: not a bundler asset shape even if followed by ".js".
	if looksLikeBundlerAssetFilename("nohyphenhere12345678", []byte("nohyphenhere12345678.js"), 20) {
		t.Error("token without a hyphen must NOT be treated as a bundler asset")
	}
	// Hyphen present but no static-asset extension follows: leave alone.
	if looksLikeBundlerAssetFilename("some-hyphenated-secret-value", []byte(`some-hyphenated-secret-value"`), 28) {
		t.Error("hyphenated token without a trailing asset extension must NOT be treated as a bundler asset")
	}
}

func TestFromData_RejectsBundlerAssetFilename(t *testing.T) {
	// Real shape from laravel/framework's
	// tests/Foundation/fixtures/prefetching-manifest.json (a Vite build
	// manifest). "password" here stands in for the ResetPassword.vue /
	// ConfirmPassword.vue entries that put a "password"-keyword hit
	// within radius of these asset names in the real file.
	chunk := []byte(`{
  "_AuthenticatedLayout-DfWF52N1.js": {
    "file": "assets/AuthenticatedLayout-DfWF52N1.js",
    "name": "AuthenticatedLayout"
  },
  "resources/js/Pages/Auth/ResetPassword.vue": {
    "file": "assets/ResetPassword-BNl7a4X1.js",
    "name": "ResetPassword"
  }
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(string(r.Raw), "AuthenticatedLayout") || strings.Contains(string(r.Raw), "ResetPassword") {
			t.Errorf("bundler content-hash filename must NOT fire; got %q", r.Raw)
		}
	}
}

func TestLooksLikeMimeType(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"application/x-www-form-urlencoded", true},
		{"multipart/form-data", true},
		{"text/plain", true},
		{"Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01", false}, // no slash
		{"com/aws/aws-sdk-go-v2", false},                          // 2 slashes — not this shape either way
		{"AKIAIOSFODNN7EXAMPLE", false},
	}
	for _, c := range cases {
		if got := looksLikeMimeType(c.s); got != c.want {
			t.Errorf("looksLikeMimeType(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestFromData_RejectsMimeType(t *testing.T) {
	// Real shape from axios's docs/pages/advanced/config-defaults.md.
	chunk := []byte(`axios.defaults.headers.common["Authorization"] = AUTH_TOKEN;
axios.defaults.headers.post["Content-Type"] =
  "application/x-www-form-urlencoded";
`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(string(r.Raw), "application/x-www-form-urlencoded") {
			t.Errorf("MIME-type string must NOT fire; got %q", r.Raw)
		}
	}
}

func TestDecodesToPrintableText(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"QWxhZGRpbjpvcGVuIHNlc2FtZQ==", true},                    // RFC 7617 "Aladdin:open sesame"
		{"Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01", false}, // real-shaped random secret
		{"AKIAIOSFODNN7EXAMPLE", false},
	}
	for _, c := range cases {
		if got := decodesToPrintableText(c.s); got != c.want {
			t.Errorf("decodesToPrintableText(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestFromData_RejectsBase64PlaceholderText(t *testing.T) {
	// Real shape from axios's tests/browser/basicAuth.browser.test.js —
	// RFC 7617's canonical Basic-Auth example, base64-encoded.
	chunk := []byte(`expect(request.requestHeaders.Authorization).toBe('Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==');`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(string(r.Raw), "QWxhZGRpbjpvcGVu") {
			t.Errorf("well-known base64 doc-example credential must NOT fire; got %q", r.Raw)
		}
	}
}

func TestFromData_StillFiresOnLaravelAppKeyShapedSecret(t *testing.T) {
	// Recall control: a Laravel APP_KEY-shaped value (base64:<32
	// random bytes>) must still fire even in a hash-dense test file,
	// mirroring what actually fired (and must keep firing) in
	// laravel/framework's RehashOnLogoutOtherDevicesTest.php. The value
	// below is freshly generated random bytes, not copied from any real
	// repo or corpus.
	chunk := []byte(`#[WithConfig('app.key', 'base64:OQyMfXJHNCzYEA8vb3cNZdZw5Y4DUdiujk9urDQvwjE=')]
class RehashOnLogoutOtherDevicesTest extends TestCase
{
    protected function defineRoutes($router)
    {
        $router->post('logout', function (Request $request) {
            auth()->logoutOtherDevices($request->input('password'));
        });
    }
}
`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	found := false
	for _, r := range res {
		if strings.Contains(string(r.Raw), "OQyMfXJHNCzYEA8vb3cNZdZw5Y4DUdiujk9urDQvwjE") {
			found = true
		}
	}
	if !found {
		t.Error("Laravel APP_KEY-shaped secret must still fire in a bcrypt/argon2-hash-dense test file")
	}
}
