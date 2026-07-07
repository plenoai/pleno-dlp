//go:build detector_unit

package jsonconfigsecret

import (
	"context"
	"testing"
)

func TestFromData_SFTPEditorConfig(t *testing.T) {
	data := []byte(`{
    "type": "sftp",
    "host": "example.com",
    "user": "root",
    "password": "hunter22Zz8k",
    "port": "22"
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "hunter22Zz8k" {
		t.Fatalf("got %q", res[0].Raw)
	}
	if res[0].ExtraData["key"] != "password" {
		t.Fatalf("key = %q", res[0].ExtraData["key"])
	}
}

func TestFromData_FtpconfigBarePass(t *testing.T) {
	data := []byte(`{
    "protocol": "sftp",
    "host": "example.com",
    "user": "root",
    "pass": "hunter22Zz8k",
    "passphrase": "swordfishR3pl"
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 2 {
		t.Fatalf("expected 2, got %d: %+v", len(res), res)
	}
}

func TestFromData_HerokuAPIKey(t *testing.T) {
	data := []byte(`{
    "heroku": {
      "HEROKU_EMAIL": "heroku@example.com",
      "HEROKU_API_KEY": "7a2f9a4289e530bef6dbf31f4cbf63d5"
    }
  }`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "7a2f9a4289e530bef6dbf31f4cbf63d5" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_RobomongoNestedUserPassword(t *testing.T) {
	data := []byte(`{
      "connections" : [
       {
        "credentials" : [
         {
          "userName" : "mongouser",
          "userPassword" : "mongopassR3al9"
         }
        ],
        "sshUserPassword" : "roboMongoSSHPassR3al"
       }
      ]
   }`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 2 {
		t.Fatalf("expected 2, got %d: %+v", len(res), res)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"placeholder password", `{"host":"x","password":"changeme"}`},
		{"literal password field value", `{"password":"password"}`},
		{"literal pass field value", `{"pass":"pass"}`},
		{"boolean value not quoted", `{"promptForPass": false}`},
		{"non-credential key", `{"username":"root","host":"example.com"}`},
		{"key contains pass but not exact/known", `{"compassDirection":"north-east-value"}`},
		{"too short", `{"password":"ab"}`},
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
	data := []byte(`{"password":"hunter22Zz8k"}` + "\n" + `{"password":"hunter22Zz8k"}`)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1 deduped, got %d", len(res))
	}
}
