package contextextract

import (
	"strings"
	"testing"
)

func TestFindNearbyUUID_TenantID(t *testing.T) {
	uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	data := []byte(`export AZURE_TENANT_ID=` + uuid + ` AZURE_CLIENT_SECRET=hunter2`)

	// Anchor is the secret ("hunter2"), not the UUID.
	anchorStart := strings.Index(string(data), "hunter2")
	anchorEnd := anchorStart + len("hunter2")

	got, ok := FindNearbyUUID(data, anchorStart, anchorEnd, []string{"tenant_id", "tenantid"}, 200)
	if !ok {
		t.Fatal("expected UUID to be found")
	}
	if got != uuid {
		t.Fatalf("got %q, want %q", got, uuid)
	}
}

func TestFindNearbyUUID_CaseInsensitiveKeyword(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"
	data := []byte(`config Tenant_Id: ` + uuid + ` secret=mypass done`)

	// Anchor is the secret value, not the UUID.
	anchorStart := strings.Index(string(data), "mypass")
	anchorEnd := anchorStart + len("mypass")

	got, ok := FindNearbyUUID(data, anchorStart, anchorEnd, []string{"tenant_id"}, 100)
	if !ok {
		t.Fatal("expected UUID found with case-insensitive keyword")
	}
	if got != uuid {
		t.Fatalf("got %q, want %q", got, uuid)
	}
}

func TestFindNearbyUUID_NoKeywordNearby(t *testing.T) {
	uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	// Put keyword far away — beyond maxRadius.
	data := []byte(uuid + strings.Repeat(" ", 500) + "tenant_id")

	_, ok := FindNearbyUUID(data, 0, len(uuid), []string{"tenant_id"}, 50)
	if ok {
		t.Fatal("expected no UUID when keyword is outside maxRadius")
	}
}

func TestFindNearbyUUID_NoMatch(t *testing.T) {
	data := []byte(`no uuid here, tenant_id=foobar`)

	_, ok := FindNearbyUUID(data, 0, 10, []string{"tenant_id"}, 200)
	if ok {
		t.Fatal("expected no UUID in data without one")
	}
}

func TestFindNearbyUUID_ReturnsNearest(t *testing.T) {
	far := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	near := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	// Anchor is at position 100. Put near UUID closer to anchor.
	data := []byte(
		"tenant_id " + far +
			strings.Repeat(" ", 30) +
			"SECRET=" +
			strings.Repeat("x", 10) +
			" tenant_id " + near + " end",
	)

	// Anchor in the middle, near "SECRET=".
	anchorStart := strings.Index(string(data), "SECRET=")
	anchorEnd := anchorStart + 7

	got, ok := FindNearbyUUID(data, anchorStart, anchorEnd, []string{"tenant_id"}, 200)
	if !ok {
		t.Fatal("expected UUID to be found")
	}
	if got != near {
		t.Fatalf("got %q, want nearest %q", got, near)
	}
}

func TestFindNearbyKeyValue_AssignmentFormat(t *testing.T) {
	data := []byte(`export AZURE_TENANT_ID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 done`)

	got, ok := FindNearbyKeyValue(data, "AZURE_TENANT_ID", 200)
	if !ok {
		t.Fatal("expected key-value found")
	}
	want := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFindNearbyKeyValue_ColonFormat(t *testing.T) {
	data := []byte(`config: azure_tenant_id: my-tenant-123`)

	got, ok := FindNearbyKeyValue(data, "azure_tenant_id", 200)
	if !ok {
		t.Fatal("expected key-value found with colon format")
	}
	if got != "my-tenant-123" {
		t.Fatalf("got %q, want %q", got, "my-tenant-123")
	}
}

func TestFindNearbyKeyValue_JSONFormat(t *testing.T) {
	data := []byte(`{"tenantId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "secret": "xxx"}`)

	got, ok := FindNearbyKeyValue(data, "tenantId", 200)
	if !ok {
		t.Fatal("expected key-value found in JSON format")
	}
	want := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFindNearbyKeyValue_QuotedValue(t *testing.T) {
	data := []byte(`TENANT_ID="some-value-here" OTHER=x`)

	got, ok := FindNearbyKeyValue(data, "TENANT_ID", 200)
	if !ok {
		t.Fatal("expected key-value found with quoted value")
	}
	if got != "some-value-here" {
		t.Fatalf("got %q, want %q", got, "some-value-here")
	}
}

func TestFindNearbyKeyValue_NoMatch(t *testing.T) {
	data := []byte(`nothing relevant here`)

	_, ok := FindNearbyKeyValue(data, "TENANT_ID", 200)
	if ok {
		t.Fatal("expected no match")
	}
}

func TestFindNearbyHost_AzureCR(t *testing.T) {
	data := []byte(`login to myregistry.azurecr.io with password AAAA=`)
	anchorStart := strings.Index(string(data), "AAAA=")

	got, ok := FindNearbyHost(data, anchorStart, ".azurecr.io", 200)
	if !ok {
		t.Fatal("expected host found")
	}
	if got != "myregistry.azurecr.io" {
		t.Fatalf("got %q, want %q", got, "myregistry.azurecr.io")
	}
}

func TestFindNearbyHost_SubdomainHost(t *testing.T) {
	data := []byte(`registry: my-org.azurecr.io secret=abc123`)
	anchorStart := strings.Index(string(data), "abc123")

	got, ok := FindNearbyHost(data, anchorStart, ".azurecr.io", 200)
	if !ok {
		t.Fatal("expected host found")
	}
	if got != "my-org.azurecr.io" {
		t.Fatalf("got %q, want %q", got, "my-org.azurecr.io")
	}
}

func TestFindNearbyHost_NoMatch(t *testing.T) {
	data := []byte(`no host here, just password=xyz`)

	_, ok := FindNearbyHost(data, 20, ".azurecr.io", 200)
	if ok {
		t.Fatal("expected no host match")
	}
}

func TestFindNearbyHost_OutOfRadius(t *testing.T) {
	data := []byte(`myregistry.azurecr.io` + strings.Repeat(" ", 500) + `secret=abc123`)
	anchorStart := strings.Index(string(data), "secret=")

	_, ok := FindNearbyHost(data, anchorStart, ".azurecr.io", 50)
	if ok {
		t.Fatal("expected no host when outside radius")
	}
}

func TestFindNearbyHost_ReturnsNearest(t *testing.T) {
	data := []byte(`far-reg.azurecr.io ` + strings.Repeat(" ", 40) + `secret=x near-reg.azurecr.io end`)
	anchorStart := strings.Index(string(data), "secret=")

	got, ok := FindNearbyHost(data, anchorStart, ".azurecr.io", 200)
	if !ok {
		t.Fatal("expected host found")
	}
	if got != "near-reg.azurecr.io" {
		t.Fatalf("got %q (expected nearest), want %q", got, "near-reg.azurecr.io")
	}
}

func TestFindNearbyUUID_OverlappingAnchor(t *testing.T) {
	// The anchor itself is a UUID — should not be returned as context.
	uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	other := "99999999-8888-7777-6666-555555555555"
	data := []byte(`tenant_id ` + uuid + ` tenant_id ` + other)

	// Anchor covers the first UUID exactly.
	got, ok := FindNearbyUUID(data, 10, 10+len(uuid), []string{"tenant_id"}, 200)
	if !ok {
		t.Fatal("expected second UUID to be found")
	}
	if got != other {
		t.Fatalf("got %q, want non-anchor UUID %q", got, other)
	}
}
