// Package aws maps an AWS access key pair to its principal (STS
// GetCallerIdentity) and, for IAM users, the attached, inline, and
// group-inherited policies.
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
}

// listResult collects every <member> and <IsTruncated> anywhere in an IAM
// ListX response, whose wrapper element names differ per action.
type listResult struct {
	Members     []member
	IsTruncated bool
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
			if mb.PolicyName == "" && mb.GroupName == "" {
				mb.PolicyName = mb.Text
			}
			l.Members = append(l.Members, mb)
		case "IsTruncated":
			var s string
			if err := d.DecodeElement(&s, &se); err != nil {
				return err
			}
			l.IsTruncated = strings.TrimSpace(s) == "true"
		default:
			depth++
		}
	}
}

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
	kind, name := principal(arn)
	am.Identity = detectors.AccessIdentity{ID: arn, Name: name, Type: kind, Account: ident.Result.Account}
	if kind == "root" {
		am.Privileged = true
		am.Permissions = append(am.Permissions, "*")
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "account", Name: ident.Result.Account, Permissions: []string{"*"}})
		return am, nil
	}
	if kind != "user" {
		am.Limitations = append(am.Limitations, "policy enumeration implemented for IAM users only; "+kind+" policies not resolved")
		return am, nil
	}
	iamURL := firstNonEmpty(m.IAMURL, "https://iam.amazonaws.com")
	list := func(action, group string) []member {
		v := url.Values{"Action": {action}, "Version": {"2010-05-08"}}
		if group != "" {
			v.Set("GroupName", group)
		} else {
			v.Set("UserName", name)
		}
		var out listResult
		if err := m.call(ctx, cred, "iam", iamURL, v, &out); err != nil {
			am.Limitations = append(am.Limitations, action+": "+err.Error())
			return nil
		}
		if out.IsTruncated {
			am.Limitations = append(am.Limitations, action+": result truncated")
		}
		return out.Members
	}
	addPolicy := func(source, pname string) {
		res := detectors.AccessResource{Type: "iam_policy", Name: pname, Permissions: []string{source}}
		am.Resources = append(am.Resources, res)
		am.Permissions = append(am.Permissions, "policy:"+pname)
		if privilegedPolicies[pname] {
			am.Privileged = true
		}
	}
	for _, p := range list("ListAttachedUserPolicies", "") {
		addPolicy("attached", p.PolicyName)
	}
	for _, p := range list("ListUserPolicies", "") {
		addPolicy("inline", p.PolicyName)
	}
	for _, g := range list("ListGroupsForUser", "") {
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "iam_group", Name: g.GroupName, Permissions: []string{"member"}})
		for _, p := range list("ListAttachedGroupPolicies", g.GroupName) {
			addPolicy("group:"+g.GroupName, p.PolicyName)
		}
		for _, p := range list("ListGroupPolicies", g.GroupName) {
			addPolicy("group-inline:"+g.GroupName, p.PolicyName)
		}
	}
	am.Limitations = append(am.Limitations, "policy documents not evaluated; permissions are reported as policy names")
	return am, nil
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
