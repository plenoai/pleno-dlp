package teams

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestMapAccess(t *testing.T) {
	am, err := Mapper{}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "https://acme.webhook.office.com/webhookb2/wid@tid/IncomingWebhook/abc/def"})
	if err != nil || am.Identity.ID != "wid" || am.Identity.Account != "tid" || am.Identity.Type != "workflow_webhook" || am.Resources[0].Name != "acme" {
		t.Fatalf("%+v %v", am, err)
	}
	for _, bad := range []string{"http://acme.webhook.office.com/webhookb2/a@b", "https://evil.com/webhookb2/a@b", "https://acme.webhook.office.com.evil.com/webhookb2/a@b", "https://u:p@outlook.office.com/webhook/a@b", "https://outlook.office.com/other"} {
		if _, err := (Mapper{}).MapAccess(context.Background(), detectors.AccessCredential{Secret: bad}); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
}
