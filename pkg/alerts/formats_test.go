package alerts

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestInferFormatChatHosts(t *testing.T) {
	for raw, want := range map[string]Format{
		"https://discord.com/api/webhooks/1/x":      FormatDiscord,
		"https://discordapp.com/api/webhooks/1/x":   FormatDiscord,
		"https://chat.googleapis.com/v1/spaces/X/m": FormatGoogleChat,
		"https://mattermost.example.com/hooks/abc":  FormatGeneric,
		"https://hooks.slack.com/services/T/B/x":    FormatSlack,
	} {
		u, _ := url.Parse(raw)
		if got := InferFormat(u); got != want {
			t.Errorf("%s: got %s want %s", raw, got, want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	if f, err := ParseFormat("auto"); err != nil || f != "" {
		t.Fatalf("auto: %q %v", f, err)
	}
	if f, err := ParseFormat("Mattermost"); err != nil || f != FormatMattermost {
		t.Fatalf("mattermost: %q %v", f, err)
	}
	if _, err := ParseFormat("irc"); err == nil {
		t.Fatal("irc accepted")
	}
}

func TestChatPayloadShapes(t *testing.T) {
	fs := []Finding{{Detector: "AWS", Severity: "critical", Verdict: "verified", Redacted: "AKIA****", Location: "a.txt:1"}}
	s := BuildSummary("v1", "filesystem", 0, fs)
	cases := map[Format]func(map[string]any) bool{
		FormatDiscord: func(m map[string]any) bool {
			e := m["embeds"].([]any)[0].(map[string]any)
			return e["color"].(float64) == 0x8B0000 && strings.Contains(e["description"].(string), "AKIA****")
		},
		FormatMattermost: func(m map[string]any) bool {
			a := m["attachments"].([]any)[0].(map[string]any)
			return a["color"] == "#8B0000" && strings.Contains(a["text"].(string), "a.txt:1")
		},
		FormatGoogleChat: func(m map[string]any) bool {
			c := m["cardsV2"].([]any)[0].(map[string]any)["card"].(map[string]any)
			w := c["sections"].([]any)[0].(map[string]any)["widgets"].([]any)
			return len(w) == 1
		},
	}
	for f, ok := range cases {
		b, err := Payload(f, s)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil || !ok(m) {
			t.Errorf("%s payload wrong: %s", f, b)
		}
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	got := truncate(strings.Repeat("あ", 10), 10)
	if !utf8.ValidString(got) || len(got) > 10 {
		t.Fatalf("bad truncate %q", got)
	}
}
