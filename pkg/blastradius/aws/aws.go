// Package aws maps an AWS access key pair to its principal (STS
// GetCallerIdentity), the attached, inline, and group-inherited policies of
// an IAM user or assumed role, the effective allow/deny actions evaluated
// from those policy documents, role-assumption paths derived from role trust
// policies, and the key's last-used activity.
package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Mapper implements detectors.AccessMapper for AWS access keys. Secret is the
// access key id, Secondary the secret access key, and Extra["session_token"]
// an optional STS session token.
type Mapper struct {
	STSURL string // default https://sts.amazonaws.com
	IAMURL string // default https://iam.amazonaws.com
	Region string // signing region, default us-east-1
	Client *http.Client
	Now    func() time.Time
}

var privilegedPolicies = map[string]bool{
	"AdministratorAccess": true, "PowerUserAccess": true, "IAMFullAccess": true,
	"AWSOrganizationsFullAccess": true,
}

type member struct {
	Text       string `xml:",chardata"`
	PolicyName string `xml:"PolicyName"`
	PolicyArn  string `xml:"PolicyArn"`
	GroupName  string `xml:"GroupName"`
	RoleName   string `xml:"RoleName"`
	Arn        string `xml:"Arn"`
	// AssumeRolePolicyDocument is the URL-encoded trust policy (ListRoles).
	AssumeRolePolicyDocument string `xml:"AssumeRolePolicyDocument"`
}

// listResult collects every <member> and <IsTruncated> anywhere in an IAM
// ListX response, whose wrapper element names differ per action.
type listResult struct {
	Members     []member
	IsTruncated bool
	Marker      string
}

func (l *listResult) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	depth := 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if _, end := tok.(xml.EndElement); end {
			if depth == 0 {
				return nil
			}
			depth--
			continue
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "member":
			var mb member
			if err := d.DecodeElement(&mb, &se); err != nil {
				return err
			}
			mb.Text = strings.TrimSpace(mb.Text)
			if mb.PolicyName == "" && mb.GroupName == "" && mb.RoleName == "" {
				mb.PolicyName = mb.Text
			}
			l.Members = append(l.Members, mb)
		case "IsTruncated":
			var s string
			if err := d.DecodeElement(&s, &se); err != nil {
				return err
			}
			l.IsTruncated = strings.TrimSpace(s) == "true"
		case "Marker":
			var s string
			if err := d.DecodeElement(&s, &se); err != nil {
				return err
			}
			l.Marker = strings.TrimSpace(s)
		default:
			depth++
		}
	}
}

// MaxRoles caps the ListRoles walk used for role-assumption paths.
const MaxRoles = 1000

func (m Mapper) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	if cred.Secret == "" || cred.Secondary == "" {
		return nil, errors.New("aws: access key id and secret access key are both required")
	}
	var ident struct {
		Result struct {
			Arn     string `xml:"Arn"`
			UserID  string `xml:"UserId"`
			Account string `xml:"Account"`
		} `xml:"GetCallerIdentityResult"`
	}
	if err := m.call(ctx, cred, "sts", firstNonEmpty(m.STSURL, "https://sts.amazonaws.com"),
		url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}, &ident); err != nil {
		return nil, fmt.Errorf("aws: identity: %w", err)
	}
	am := detectors.NewAccessMap("aws")
	arn := ident.Result.Arn
	account := ident.Result.Account
	kind, name := principal(arn)
	am.Identity = detectors.AccessIdentity{ID: arn, Name: name, Type: kind, Account: account}
	iamURL := firstNonEmpty(m.IAMURL, "https://iam.amazonaws.com")
	iam := func(action string, kv ...string) url.Values {
		v := url.Values{"Action": {action}, "Version": {"2010-05-08"}}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	m.lastUsed(ctx, cred, iamURL, am, iam)
	if kind == "root" {
		am.Privileged = true
		am.Permissions = append(am.Permissions, "*")
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "account", Name: account, Permissions: []string{"*"}})
		return am, nil
	}
	var ownerKey, owner string
	switch kind {
	case "user":
		ownerKey, owner = "UserName", name
	case "assumed-role":
		ownerKey, owner = "RoleName", strings.SplitN(name, "/", 2)[0]
	default:
		am.Limitations = append(am.Limitations, "policy enumeration not implemented for "+kind+" principals")
		return am, nil
	}
	list := func(v url.Values) []member {
		var all []member
		for page := 0; page < 20; page++ {
			var out listResult
			if err := m.call(ctx, cred, "iam", iamURL, v, &out); err != nil {
				am.Limitations = append(am.Limitations, v.Get("Action")+": "+err.Error())
				return all
			}
			all = append(all, out.Members...)
			if !out.IsTruncated {
				return all
			}
			if out.Marker == "" || page == 19 {
				am.Limitations = append(am.Limitations, v.Get("Action")+": result truncated")
				return all
			}
			v.Set("Marker", out.Marker)
		}
		return all
	}
	eval := newEvaluation()
	docsOK := true
	addDoc := func(label, doc string) {
		stmts, err := parsePolicy(doc)
		if err != nil {
			am.Limitations = append(am.Limitations, "policy "+label+": undecodable document")
			docsOK = false
			return
		}
		eval.add(stmts)
	}
	managedDoc := func(policyArn string) {
		if policyArn == "" {
			docsOK = false
			return
		}
		var gp struct {
			Version string `xml:"GetPolicyResult>Policy>DefaultVersionId"`
		}
		if err := m.call(ctx, cred, "iam", iamURL, iam("GetPolicy", "PolicyArn", policyArn), &gp); err != nil {
			am.Limitations = append(am.Limitations, "GetPolicy: "+err.Error())
			docsOK = false
			return
		}
		var pv struct {
			Document string `xml:"GetPolicyVersionResult>PolicyVersion>Document"`
		}
		if err := m.call(ctx, cred, "iam", iamURL, iam("GetPolicyVersion", "PolicyArn", policyArn, "VersionId", gp.Version), &pv); err != nil {
			am.Limitations = append(am.Limitations, "GetPolicyVersion: "+err.Error())
			docsOK = false
			return
		}
		addDoc(policyArn, pv.Document)
	}
	inlineDoc := func(action, key, ownerName, policy string) {
		var r struct {
			User  string `xml:"GetUserPolicyResult>PolicyDocument"`
			Role  string `xml:"GetRolePolicyResult>PolicyDocument"`
			Group string `xml:"GetGroupPolicyResult>PolicyDocument"`
		}
		if err := m.call(ctx, cred, "iam", iamURL, iam(action, key, ownerName, "PolicyName", policy), &r); err != nil {
			am.Limitations = append(am.Limitations, action+": "+err.Error())
			docsOK = false
			return
		}
		addDoc(policy, firstNonEmpty(r.User, r.Role, r.Group))
	}
	addPolicy := func(source, pname string) {
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "iam_policy", Name: pname, Permissions: []string{source}})
		am.Permissions = append(am.Permissions, "policy:"+pname)
		if privilegedPolicies[pname] {
			am.Privileged = true
		}
	}
	entity := strings.TrimSuffix(ownerKey, "Name") // User | Role
	for _, p := range list(iam("ListAttached"+entity+"Policies", ownerKey, owner)) {
		addPolicy("attached", p.PolicyName)
		managedDoc(p.PolicyArn)
	}
	for _, p := range list(iam("List"+entity+"Policies", ownerKey, owner)) {
		addPolicy("inline", p.PolicyName)
		inlineDoc("Get"+entity+"Policy", ownerKey, owner, p.PolicyName)
	}
	if kind == "user" {
		for _, g := range list(iam("ListGroupsForUser", "UserName", owner)) {
			am.Resources = append(am.Resources, detectors.AccessResource{Type: "iam_group", Name: g.GroupName, Permissions: []string{"member"}})
			for _, p := range list(iam("ListAttachedGroupPolicies", "GroupName", g.GroupName)) {
				addPolicy("group:"+g.GroupName, p.PolicyName)
				managedDoc(p.PolicyArn)
			}
			for _, p := range list(iam("ListGroupPolicies", "GroupName", g.GroupName)) {
				addPolicy("group-inline:"+g.GroupName, p.PolicyName)
				inlineDoc("GetGroupPolicy", "GroupName", g.GroupName, p.PolicyName)
			}
		}
	}

	// Effective permissions from the evaluated documents.
	for _, a := range sortedKeys(eval.allow) {
		am.Permissions = append(am.Permissions, "allow:"+a)
	}
	for _, a := range sortedKeys(eval.deny) {
		am.Permissions = append(am.Permissions, "deny:"+a)
	}
	byResource := map[string]map[string]bool{}
	for a, rs := range eval.allow {
		for r := range rs {
			if byResource[r] == nil {
				byResource[r] = map[string]bool{}
			}
			byResource[r][a] = true
		}
	}
	for _, r := range sortedKeys(byResource) {
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "aws_resource", Name: r, Permissions: sortedSet(byResource[r])})
	}
	if eval.privileged() {
		am.Privileged = true
	}

	// Role-assumption paths: roles whose trust policy admits this principal
	// (directly, or via its account when the identity policy allows
	// sts:AssumeRole on the role), plus identity-policy AssumeRole targets.
	assumable := map[string]string{}
	roles := list(iam("ListRoles", "MaxItems", "1000"))
	if len(roles) > MaxRoles {
		roles = roles[:MaxRoles]
		am.Limitations = append(am.Limitations, fmt.Sprintf("ListRoles: capped at %d", MaxRoles))
	}
	callerARN := arn
	if kind == "assumed-role" {
		callerARN = "arn:aws:iam::" + account + ":role/" + owner
	}
	for _, r := range roles {
		if r.Arn == "" || r.Arn == callerARN {
			continue
		}
		stmts, err := parsePolicy(r.AssumeRolePolicyDocument)
		if err != nil {
			continue
		}
		switch how := trusts(stmts, callerARN, account); how {
		case "direct":
			assumable[r.Arn] = "trust:direct"
		case "account", "any":
			if eval.allows("sts:AssumeRole", r.Arn) {
				assumable[r.Arn] = "trust:" + how
			}
		}
	}
	for a, rs := range eval.allow {
		if !glob(a, "sts:AssumeRole") {
			continue
		}
		for r := range rs {
			if strings.Contains(r, ":role/") && !strings.ContainsAny(r, "*?") {
				if _, ok := assumable[r]; !ok {
					assumable[r] = "identity-policy (trust unverified)"
				}
			}
		}
	}
	for _, r := range sortedSet(boolKeys(assumable)) {
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "assumable_role", Name: r, Permissions: []string{"sts:AssumeRole", assumable[r]}})
	}
	if !docsOK {
		am.Limitations = append(am.Limitations, "some policy documents could not be read; effective permissions are partial")
	}
	if eval.notAction {
		am.Limitations = append(am.Limitations, "NotAction statements recorded, not expanded")
	}
	if eval.conditions {
		am.Limitations = append(am.Limitations, "policy conditions not evaluated")
	}
	am.Limitations = append(am.Limitations, "permission boundaries, SCPs and resource policies not applied")
	return am, nil
}

func boolKeys(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

// lastUsed records GetAccessKeyLastUsed activity. Temporary (ASIA) keys
// have no last-used record.
func (m Mapper) lastUsed(ctx context.Context, cred detectors.AccessCredential, iamURL string, am *detectors.AccessMap, iam func(string, ...string) url.Values) {
	if strings.HasPrefix(cred.Secret, "ASIA") {
		return
	}
	var r struct {
		Date    string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>LastUsedDate"`
		Service string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>ServiceName"`
		Region  string `xml:"GetAccessKeyLastUsedResult>AccessKeyLastUsed>Region"`
	}
	if err := m.call(ctx, cred, "iam", iamURL, iam("GetAccessKeyLastUsed", "AccessKeyId", cred.Secret), &r); err != nil {
		am.Limitations = append(am.Limitations, "GetAccessKeyLastUsed: "+err.Error())
		return
	}
	if r.Date == "" {
		am.Activity = &detectors.AccessActivity{Service: "N/A"}
		return
	}
	am.Activity = &detectors.AccessActivity{LastUsed: r.Date, Service: r.Service, Region: r.Region}
}

func (m Mapper) call(ctx context.Context, cred detectors.AccessCredential, service, endpoint string, form url.Values, dst any) error {
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+"/", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	sum := sha256.Sum256([]byte(body))
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	creds := awssdk.Credentials{AccessKeyID: cred.Secret, SecretAccessKey: cred.Secondary, SessionToken: cred.Extra["session_token"]}
	if err := v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), service, firstNonEmpty(m.Region, "us-east-1"), now()); err != nil {
		return err
	}
	resp, err := httpx.Client(m.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, httpx.MaxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &httpx.StatusError{Code: resp.StatusCode, URL: service + ":" + form.Get("Action")}
	}
	return xml.Unmarshal(data, dst)
}

// principal returns the coarse principal kind and its short name from an ARN.
func principal(arn string) (kind, name string) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "other", arn
	}
	res := parts[5]
	switch {
	case res == "root":
		return "root", "root"
	case strings.HasPrefix(res, "user/"):
		s := strings.TrimPrefix(res, "user/")
		return "user", s[strings.LastIndex(s, "/")+1:]
	case strings.HasPrefix(res, "assumed-role/"):
		return "assumed-role", strings.TrimPrefix(res, "assumed-role/")
	case strings.HasPrefix(res, "federated-user/"):
		return "federated-user", strings.TrimPrefix(res, "federated-user/")
	}
	return "other", res
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
