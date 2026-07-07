//go:build detector_unit

package phpconfigsecret

import (
	"context"
	"testing"
)

func TestFromData_WPConfigStyle(t *testing.T) {
	// Shaped like wp-config.php: one known-key define() with a
	// low-entropy placeholder value (suppressed — see the "admin
	// placeholder" test below) plus WordPress-style random-punctuation
	// salts, interleaved with informative (non-secret) define() calls
	// that must NOT be flagged.
	data := []byte(`<?php
define( 'DB_NAME',     'main' );
define( 'DB_USER',     'admin' );
define( 'DB_HOST',     'localhost' );
define('AUTH_KEY',         'MW1pxMctoyA(>M%0Vl 2(#o0|2$cB+K|.G$hB~4` + "`" + `Juw@]:(5;oVUl<<W3^e_R-fg');
define('SECURE_AUTH_KEY',  'Y>Y9.5Ch0-3cq|=vbus[IeF(OJ9yZ|SQ#:iG;NSa+GJmj _1Ed(cVZ7r#+JMlA,S');
define('LOGGED_IN_KEY',    'Q$:B]zZjN-AdT<>h7V1.vm+k^|}2wVZf]Xw#QEZ[-pSohv+Kj0W-Z|:|g$-+E8:8');
define('NONCE_KEY',        '}Fi>>0a{> akEdJ1K3c}([(:x;K[)ZQ3F3cttcpd EFORd.%R|*|rdRs#-L-&)P1');
define('AUTH_SALT',        'j@cGIZJfObpPU);AZgYH5,ubbSlUp|ZnLZNlq|;tkFe5xc(=_0[LKbF71T.EE ~9');
define('SECURE_AUTH_SALT', 'Ed&1cr+{3T$a+{[8LP~i5-[|Z` + "`" + `x-V>;Di_C/E~UnSg{n[h#{D[-t>yIUZ8YqSu3t');
define('LOGGED_IN_SALT',   'of@~yp:v@SK;Y}hzUo4=bz9WmX&vEw5TO dD$<2djGcE+Qz,Sb9i:{+U<#eM-RmE');
define('NONCE_SALT',       ':9URM*n56|I|Rf$|ud0cFJ<KAA<1h_w]A!/?])<q+!qK>+Lq&j9^-!{%%pW. ,Z=');
`)
	res, err := Scanner{}.FromData(context.Background(), false, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 8 {
		t.Fatalf("expected 8 (the 8 salts/keys; DB_NAME/DB_USER/DB_HOST are informative), got %d: %+v", len(res), res)
	}
	keys := map[string]bool{}
	for _, r := range res {
		keys[r.ExtraData["key"]] = true
	}
	for _, want := range []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"} {
		if !keys[want] {
			t.Errorf("missing expected key %q in results", want)
		}
	}
}

func TestFromData_DBPasswordPlaceholderSuppressed(t *testing.T) {
	// DB_PASSWORD set to the common weak/placeholder value "admin" is
	// suppressed, consistent with hardcodedpassword's and basicauth's
	// existing "admin" placeholder convention in this codebase.
	data := []byte(`define( 'DB_PASSWORD', 'admin' );` + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 0 {
		t.Fatalf("expected 0 (placeholder), got %d: %+v", len(res), res)
	}
}

func TestFromData_DBPasswordRealValue(t *testing.T) {
	data := []byte(`define( 'DB_PASSWORD', 'Zx9-Krypton-Whale7' );` + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "Zx9-Krypton-Whale7" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_UnknownDefineKeyIgnored(t *testing.T) {
	data := []byte(`define( 'DB_NAME', 'main' );` + "\n" +
		`define( 'CACHE_KEY_PREFIX', 'app_' );` + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 0 {
		t.Fatalf("expected 0 (DB_NAME/CACHE_KEY_PREFIX are not known credential keys), got %d: %+v", len(res), res)
	}
}

func TestFromData_ConfigPHPVariableStyle(t *testing.T) {
	// Shaped like config.php: $dbpasswd has no separator before
	// "passwd" (hardcodedpassword's boundary rule would miss this);
	// $dbhost/$dbname/$dbuser are informative and must not be flagged.
	data := []byte(`<?php
    $dbms = 'mysql';
    $dbhost = 'localhost';
    $dbname = 'main';
    $dbuser = 'root';
    $dbpasswd = 'Rq4-Falcon-Ember9';
`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "Rq4-Falcon-Ember9" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["key"] != "$dbpasswd" {
		t.Fatalf("key = %q", res[0].ExtraData["key"])
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"templated define value", `define('DB_PASSWORD', '${DB_PASS}');` + "\n"},
		{"short value", `define('DB_PASSWORD', 'ab');` + "\n"},
		{"empty value", `define('DB_PASSWORD', '');` + "\n"},
		{"var placeholder changeme", `$dbpasswd = 'changeme';` + "\n"},
		{"unrelated var name", `$cachekey = 'Rq4-Falcon-Ember9';` + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 0 {
				t.Fatalf("expected 0, got %d findings for %q: %+v", len(res), tc.data, res)
			}
		})
	}
}
