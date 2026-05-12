package openaipf

// mapEntityType translates an opf raw category string into the
// wire-stable pii_kind value emitted in ExtraData["pii_kind"], per
// ADR-0004 §6.
//
// Unknown opf categories (a future upstream version that adds a
// category we have not mapped) pass through unchanged. That is
// deliberate: forwarding the raw upstream string keeps the new
// finding observable in downstream pipelines instead of silently
// dropping it on the floor. The Go side stays append-only — adding
// a mapping is a coordinated edit here plus an ADR-0004 §6
// update; never a silent rename.
//
// The mapping is intentionally not a public function. The detector
// is the only caller; exporting it would invite drift between the
// table here and the ADR-0004 §6 wire contract.
func mapEntityType(entityType string) string {
	if mapped, ok := entityTypeMap[entityType]; ok {
		return mapped
	}
	return entityType
}

// entityTypeMap is the ADR-0004 §6 wire contract. New entries land
// here and in the ADR together; the table is one-to-one with the
// "opf category → pii_kind" rows in the ADR. The keys are opf's
// own category strings (the EntityType field in piiengine/openaipf
// Finding); the values are the pleno-dlp pii_kind strings that
// downstream JSON consumers may pin against.
//
// Strings reused from anonymize ("ADDRESS", "EMAIL_ADDRESS",
// "PERSON", "PHONE_NUMBER") deliberately collide: a downstream
// consumer routing on pii_kind alone gets the same semantic regardless
// of which engine emitted the finding. ExtraData["engine"]
// distinguishes the two engines when distinction matters.
var entityTypeMap = map[string]string{
	"account_numbers":       "ACCOUNT_NUMBER",
	"private_addresses":     "ADDRESS",
	"private_emails":        "EMAIL_ADDRESS",
	"private_persons":       "PERSON",
	"private_phone_numbers": "PHONE_NUMBER",
	"private_urls":          "URL",
	"private_dates":         "DATE",
	"secrets":               "OPF_SECRET",
}
