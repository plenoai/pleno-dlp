package aws

import (
	"encoding/json"
	"net/url"
	"path"
	"sort"
	"strings"
)

// statement is one IAM policy statement with string-or-array fields
// normalized to slices.
type statement struct {
	Effect      string
	Action      []string
	NotAction   []string
	Resource    []string
	NotResource []string
	Principal   map[string][]string
	HasCond     bool
}

type stringOrSlice []string

func (s *stringOrSlice) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

type rawStatement struct {
	Effect      string          `json:"Effect"`
	Action      stringOrSlice   `json:"Action"`
	NotAction   stringOrSlice   `json:"NotAction"`
	Resource    stringOrSlice   `json:"Resource"`
	NotResource stringOrSlice   `json:"NotResource"`
	Principal   json.RawMessage `json:"Principal"`
	Condition   json.RawMessage `json:"Condition"`
}

// parsePolicy decodes an IAM policy document. IAM APIs return documents
// URL-encoded; both encoded and plain JSON are accepted.
func parsePolicy(doc string) ([]statement, error) {
	doc = strings.TrimSpace(doc)
	if !strings.HasPrefix(doc, "{") {
		if dec, err := url.QueryUnescape(doc); err == nil {
			doc = dec
		}
	}
	var raw struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &raw); err != nil {
		return nil, err
	}
	var stmts []rawStatement
	if len(raw.Statement) > 0 && raw.Statement[0] == '{' {
		var one rawStatement
		if err := json.Unmarshal(raw.Statement, &one); err != nil {
			return nil, err
		}
		stmts = []rawStatement{one}
	} else if len(raw.Statement) > 0 {
		if err := json.Unmarshal(raw.Statement, &stmts); err != nil {
			return nil, err
		}
	}
	out := make([]statement, 0, len(stmts))
	for _, r := range stmts {
		st := statement{Effect: r.Effect, Action: r.Action, NotAction: r.NotAction, Resource: r.Resource, NotResource: r.NotResource,
			HasCond: len(r.Condition) > 0 && string(r.Condition) != "null"}
		st.Principal = parsePrincipal(r.Principal)
		out = append(out, st)
	}
	return out, nil
}

func parsePrincipal(b json.RawMessage) map[string][]string {
	if len(b) == 0 {
		return nil
	}
	var star string
	if json.Unmarshal(b, &star) == nil {
		return map[string][]string{"*": {star}}
	}
	var m map[string]stringOrSlice
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	out := map[string][]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// glob matches IAM wildcards (* and ?) case-insensitively.
func glob(pattern, s string) bool {
	ok, err := path.Match(strings.ToLower(strings.ReplaceAll(pattern, "/", "\x00")), strings.ToLower(strings.ReplaceAll(s, "/", "\x00")))
	return err == nil && ok
}

func anyGlob(patterns []string, s string) bool {
	for _, p := range patterns {
		if glob(p, s) {
			return true
		}
	}
	return false
}

// escalationActions are IAM actions that let a principal widen its own or
// another principal's access; holding any on "*" marks the map privileged.
var escalationActions = []string{
	"iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
	"iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy",
	"iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy",
	"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:AddUserToGroup",
	"iam:UpdateAssumeRolePolicy", "iam:PassRole", "sts:AssumeRole",
	"lambda:UpdateFunctionCode", "organizations:*", "kms:Decrypt", "secretsmanager:GetSecretValue",
}

// evaluation is the effective allow/deny view across every policy the
// principal holds. It is an over-approximation of what IAM would authorize:
// conditions, permission boundaries, SCPs and resource policies are not
// applied, and NotAction/NotResource are recorded rather than expanded.
type evaluation struct {
	allow      map[string]map[string]bool // action -> resources
	deny       map[string]map[string]bool
	notAction  bool
	conditions bool
}

func newEvaluation() *evaluation {
	return &evaluation{allow: map[string]map[string]bool{}, deny: map[string]map[string]bool{}}
}

func (e *evaluation) add(stmts []statement) {
	for _, st := range stmts {
		target := e.allow
		if strings.EqualFold(st.Effect, "Deny") {
			target = e.deny
		}
		if st.HasCond {
			e.conditions = true
		}
		actions := st.Action
		if len(st.NotAction) > 0 {
			e.notAction = true
			actions = []string{"NotAction:" + strings.Join(st.NotAction, ",")}
		}
		resources := st.Resource
		if len(st.NotResource) > 0 {
			resources = []string{"NotResource:" + strings.Join(st.NotResource, ",")}
		}
		if len(resources) == 0 {
			resources = []string{"*"}
		}
		for _, a := range actions {
			if target[a] == nil {
				target[a] = map[string]bool{}
			}
			for _, r := range resources {
				target[a][r] = true
			}
		}
	}
}

// allows reports whether action on resource is allowed and not explicitly
// denied (wildcards on either side honoured).
func (e *evaluation) allows(action, resource string) bool {
	match := func(set map[string]map[string]bool, isAllow bool) bool {
		for a, rs := range set {
			if strings.HasPrefix(a, "NotAction:") {
				if isAllow && !anyGlob(strings.Split(strings.TrimPrefix(a, "NotAction:"), ","), action) && rs["*"] {
					return true
				}
				continue
			}
			if !glob(a, action) {
				continue
			}
			for r := range rs {
				if glob(r, resource) {
					return true
				}
			}
		}
		return false
	}
	return match(e.allow, true) && !match(e.deny, false)
}

func (e *evaluation) privileged() bool {
	if e.allows("*", "*") || e.allows("iam:*", "*") {
		return true
	}
	for _, a := range escalationActions {
		if e.allows(a, "*") {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// trusts reports whether a role trust policy lets principalARN (or its
// account) call sts:AssumeRole, and how ("direct", "account", "any").
func trusts(stmts []statement, principalARN, account string) string {
	how := ""
	for _, st := range stmts {
		if !strings.EqualFold(st.Effect, "Allow") || !anyGlob(st.Action, "sts:AssumeRole") {
			continue
		}
		for k, vs := range st.Principal {
			if k != "AWS" && k != "*" {
				continue
			}
			for _, v := range vs {
				switch {
				case v == "*":
					if how == "" {
						how = "any"
					}
				case v == principalARN || glob(v, principalARN):
					return "direct"
				case v == account || v == "arn:aws:iam::"+account+":root":
					how = "account"
				}
			}
		}
	}
	return how
}
