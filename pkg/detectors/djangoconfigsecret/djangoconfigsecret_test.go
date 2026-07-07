//go:build detector_unit

package djangoconfigsecret

import (
	"context"
	"testing"
)

func TestFromData_SecretKey(t *testing.T) {
	data := []byte(`
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'zX!9$kQ2(mP#wR_bT7vL0eN[cJ4hU8yF*sD5gA1oI]qW6eZ'

DEBUG = True
`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "zX!9$kQ2(mP#wR_bT7vL0eN[cJ4hU8yF*sD5gA1oI]qW6eZ" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["kind"] != "secret_key" {
		t.Fatalf("got kind %q", res[0].ExtraData["kind"])
	}
}

func TestFromData_DatabasePassword(t *testing.T) {
	data := []byte(`
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'appdb',
        'USER': 'appuser',
        'PASSWORD': 'MyStr0ng!DbPass9',
        'HOST': 'db.internal',
    }
}
`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "MyStr0ng!DbPass9" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["kind"] != "database_password" {
		t.Fatalf("got kind %q", res[0].ExtraData["kind"])
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"placeholder secret key", `SECRET_KEY = 'changeme'`},
		{"env-sourced secret key not a literal", `SECRET_KEY = os.environ.get('SECRET_KEY')`},
		{"placeholder db password", `'PASSWORD': 'password',`},
		{"too short db password", `'PASSWORD': 'ab',`},
		{"empty secret key", `SECRET_KEY = ''`},
		{"unrelated dict key", `'ENGINE': 'django.db.backends.sqlite3',`},
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

func TestFromData_Dedup(t *testing.T) {
	data := []byte(`
SECRET_KEY = 'zX!9$kQ2(mP#wR_bT7vL0eN[cJ4hU8yF*sD5gA1oI]qW6eZ'
SECRET_KEY = 'zX!9$kQ2(mP#wR_bT7vL0eN[cJ4hU8yF*sD5gA1oI]qW6eZ'
`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d: %+v", len(res), res)
	}
}
