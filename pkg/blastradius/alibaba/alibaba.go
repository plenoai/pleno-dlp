// Package alibaba maps an Alibaba Cloud AccessKey pair to its caller
// identity (STS GetCallerIdentity) and, for RAM users, attached policies.
package alibaba

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Mapper implements detectors.AccessMapper. Secret is the AccessKey ID and
// Secondary the AccessKey secret.
type Mapper struct {
	STSURL string // default https://sts.aliyuncs.com
	RAMURL string // default https://ram.aliyuncs.com
	Client *http.Client
	Now    func() time.Time
}

var privilegedPolicies = map[string]bool{
	"AdministratorAccess": true, "AliyunRAMFullAccess": true, "AliyunSTSAssumeRoleAccess": true,
	"AliyunResourceManagerFullAccess": true,
}

func (m Mapper) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	if cred.Secret == "" || cred.Secondary == "" {
		return nil, errors.New("alibaba: access key id and secret are both required")
	}
	var id struct {
		AccountID    string `json:"AccountId"`
		Arn          string `json:"Arn"`
		IdentityType string `json:"IdentityType"`
		PrincipalID  string `json:"PrincipalId"`
		UserID       string `json:"UserId"`
	}
	if err := m.call(ctx, cred, firstNonEmpty(m.STSURL, "https://sts.aliyuncs.com"), "GetCallerIdentity", "2015-04-01", nil, &id); err != nil {
		return nil, fmt.Errorf("alibaba: identity: %w", err)
	}
	am := detectors.NewAccessMap("alibaba")
	name := id.Arn[strings.LastIndex(id.Arn, "/")+1:]
	am.Identity = detectors.AccessIdentity{ID: id.Arn, Name: name, Type: strings.ToLower(firstNonEmpty(id.IdentityType, "unknown")), Account: id.AccountID}
	switch am.Identity.Type {
	case "account":
		am.Privileged = true
		am.Permissions = append(am.Permissions, "*")
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "account", Name: id.AccountID, Permissions: []string{"*"}})
		return am, nil
	case "ramuser":
	default:
		am.Limitations = append(am.Limitations, "policy enumeration implemented for RAM users only")
		return am, nil
	}
	var pol struct {
		Policies struct {
			Policy []struct {
				PolicyName string `json:"PolicyName"`
				PolicyType string `json:"PolicyType"`
			} `json:"Policy"`
		} `json:"Policies"`
	}
	if err := m.call(ctx, cred, firstNonEmpty(m.RAMURL, "https://ram.aliyuncs.com"), "ListPoliciesForUser", "2015-05-01", map[string]string{"UserName": name}, &pol); err != nil {
		am.Limitations = append(am.Limitations, "ListPoliciesForUser: "+err.Error())
	}
	for _, p := range pol.Policies.Policy {
		am.Permissions = append(am.Permissions, "policy:"+p.PolicyName)
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "ram_policy", Name: p.PolicyName, Permissions: []string{strings.ToLower(p.PolicyType)}})
		if privilegedPolicies[p.PolicyName] {
			am.Privileged = true
		}
	}
	am.Limitations = append(am.Limitations, "policy documents and group-inherited policies not evaluated")
	return am, nil
}

func pct(s string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(s))
}

// call issues a signed RPC-style GET (signature version 1.0, HMAC-SHA1).
func (m Mapper) call(ctx context.Context, cred detectors.AccessCredential, endpoint, action, version string, params map[string]string, dst any) error {
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	q := map[string]string{
		"Action": action, "Version": version, "Format": "JSON", "AccessKeyId": cred.Secret,
		"SignatureMethod": "HMAC-SHA1", "SignatureVersion": "1.0", "SignatureNonce": hex.EncodeToString(nonce),
		"Timestamp": now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	for k, v := range params {
		q[k] = v
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = pct(k) + "=" + pct(q[k])
	}
	canon := strings.Join(parts, "&")
	mac := hmac.New(sha1.New, []byte(cred.Secondary+"&"))
	mac.Write([]byte("GET&%2F&" + pct(canon)))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	_, err := httpx.GetJSON(ctx, m.Client, strings.TrimRight(endpoint, "/")+"/?"+canon+"&Signature="+pct(sig), nil, dst)
	return err
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
