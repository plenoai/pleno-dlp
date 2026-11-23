// Package azure maps Azure credentials: Entra ID service-principal client
// secrets (Graph app roles, directory roles, ARM RBAC role assignments per
// subscription) and storage-account shared keys (containers reachable with
// full account access).
package azure

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/blastradius/httpx"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// MaxSubscriptions caps the subscriptions whose role assignments are read.
const MaxSubscriptions = 100

var privilegedGraphRoles = map[string]bool{
	"RoleManagement.ReadWrite.Directory": true, "Application.ReadWrite.All": true,
	"AppRoleAssignment.ReadWrite.All": true, "Directory.ReadWrite.All": true,
	"User.ReadWrite.All": true, "Group.ReadWrite.All": true, "Mail.ReadWrite": true,
	"Files.ReadWrite.All": true, "Sites.FullControl.All": true,
}

var privilegedDirectoryRoles = map[string]bool{
	"Global Administrator": true, "Privileged Role Administrator": true,
	"Application Administrator": true, "Cloud Application Administrator": true,
	"Privileged Authentication Administrator": true, "User Administrator": true,
}

var privilegedRBAC = map[string]bool{
	"Owner": true, "Contributor": true, "User Access Administrator": true,
	"Role Based Access Control Administrator": true,
}

// ServicePrincipalMapper maps an Entra ID client secret. Secret is the client
// secret; Extra carries tenant_id and client_id.
type ServicePrincipalMapper struct {
	LoginURL string // default https://login.microsoftonline.com
	GraphURL string // default https://graph.microsoft.com
	ARMURL   string // default https://management.azure.com
	Client   *http.Client
}

func (m ServicePrincipalMapper) token(ctx context.Context, cred detectors.AccessCredential, scope string) (string, error) {
	login := strings.TrimRight(firstNonEmpty(m.LoginURL, "https://login.microsoftonline.com"), "/")
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cred.Extra["client_id"]},
		"client_secret": {cred.Secret}, "scope": {scope}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, login+"/"+url.PathEscape(cred.Extra["tenant_id"])+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if _, err := httpx.Do(httpx.Client(m.Client), req, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", errors.New("empty access token")
	}
	return out.AccessToken, nil
}

// jwtRoles reads the unverified "roles" claim of an access token we just
// obtained from the issuer; it is used only for reporting.
func jwtRoles(tok string) []string {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var c struct {
		Roles []string `json:"roles"`
	}
	_ = json.Unmarshal(b, &c)
	return c.Roles
}

func (m ServicePrincipalMapper) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	if cred.Extra["tenant_id"] == "" || cred.Extra["client_id"] == "" {
		return nil, errors.New("azure: tenant_id and client_id are required")
	}
	graphBase := strings.TrimRight(firstNonEmpty(m.GraphURL, "https://graph.microsoft.com"), "/")
	armBase := strings.TrimRight(firstNonEmpty(m.ARMURL, "https://management.azure.com"), "/")
	gt, err := m.token(ctx, cred, "https://graph.microsoft.com/.default")
	if err != nil {
		return nil, fmt.Errorf("azure: token: %w", err)
	}
	am := detectors.NewAccessMap("azure")
	am.Identity = detectors.AccessIdentity{ID: cred.Extra["client_id"], Type: "service_principal", Account: cred.Extra["tenant_id"]}
	for _, r := range jwtRoles(gt) {
		am.Permissions = append(am.Permissions, "graph:"+r)
		if privilegedGraphRoles[r] {
			am.Privileged = true
		}
	}
	gh := map[string]string{"Authorization": "Bearer " + gt}
	var sp struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	}
	if _, err := httpx.GetJSON(ctx, m.Client, graphBase+"/v1.0/servicePrincipals(appId='"+url.PathEscape(cred.Extra["client_id"])+"')", gh, &sp); err != nil {
		am.Limitations = append(am.Limitations, "servicePrincipal lookup: "+err.Error())
	} else {
		am.Identity.Name = sp.DisplayName
		var mem struct {
			Value []struct {
				Type        string `json:"@odata.type"`
				DisplayName string `json:"displayName"`
			} `json:"value"`
		}
		if _, err := httpx.GetJSON(ctx, m.Client, graphBase+"/v1.0/servicePrincipals/"+url.PathEscape(sp.ID)+"/memberOf", gh, &mem); err != nil {
			am.Limitations = append(am.Limitations, "memberOf: "+err.Error())
		}
		for _, v := range mem.Value {
			typ := "group"
			if strings.HasSuffix(v.Type, "directoryRole") {
				typ = "directory_role"
				if privilegedDirectoryRoles[v.DisplayName] {
					am.Privileged = true
				}
			}
			am.Resources = append(am.Resources, detectors.AccessResource{Type: typ, Name: v.DisplayName, Permissions: []string{"member"}})
		}
	}

	at, err := m.token(ctx, cred, "https://management.azure.com/.default")
	if err != nil {
		am.Limitations = append(am.Limitations, "ARM token: "+err.Error())
		return am, nil
	}
	ah := map[string]string{"Authorization": "Bearer " + at}
	var subs struct {
		Value []struct {
			ID          string `json:"subscriptionId"`
			DisplayName string `json:"displayName"`
		} `json:"value"`
	}
	if _, err := httpx.GetJSON(ctx, m.Client, armBase+"/subscriptions?api-version=2022-12-01", ah, &subs); err != nil {
		am.Limitations = append(am.Limitations, "subscriptions: "+err.Error())
		return am, nil
	}
	if len(subs.Value) > MaxSubscriptions {
		subs.Value = subs.Value[:MaxSubscriptions]
		am.Limitations = append(am.Limitations, fmt.Sprintf("subscriptions capped at %d", MaxSubscriptions))
	}
	roleNames := map[string]string{}
	for _, s := range subs.Value {
		res := detectors.AccessResource{Type: "subscription", Name: firstNonEmpty(s.DisplayName, s.ID)}
		if sp.ID != "" {
			var ras struct {
				Value []struct {
					Properties struct {
						RoleDefinitionID string `json:"roleDefinitionId"`
						Scope            string `json:"scope"`
					} `json:"properties"`
				} `json:"value"`
			}
			u := armBase + "/subscriptions/" + url.PathEscape(s.ID) + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=" + url.QueryEscape("assignedTo('"+sp.ID+"')")
			if _, err := httpx.GetJSON(ctx, m.Client, u, ah, &ras); err != nil {
				am.Limitations = append(am.Limitations, "roleAssignments "+s.ID+": "+err.Error())
			}
			for _, ra := range ras.Value {
				rd := ra.Properties.RoleDefinitionID
				name, ok := roleNames[rd]
				if !ok {
					var def struct {
						Properties struct {
							RoleName string `json:"roleName"`
						} `json:"properties"`
					}
					if _, err := httpx.GetJSON(ctx, m.Client, armBase+rd+"?api-version=2022-04-01", ah, &def); err == nil {
						name = def.Properties.RoleName
					}
					name = firstNonEmpty(name, rd[strings.LastIndex(rd, "/")+1:])
					roleNames[rd] = name
				}
				perm := name
				if ra.Properties.Scope != "/subscriptions/"+s.ID {
					perm = name + "@" + ra.Properties.Scope
				}
				res.Permissions = append(res.Permissions, perm)
				am.Permissions = append(am.Permissions, "rbac:"+perm)
				if privilegedRBAC[name] {
					am.Privileged = true
				}
			}
		}
		am.Resources = append(am.Resources, res)
	}
	am.Limitations = append(am.Limitations, "management-group role assignments and PIM-eligible roles not enumerated")
	return am, nil
}

// StorageKeyMapper maps a storage-account shared key. Secret is the base64
// account key; Extra["account"] the account name.
type StorageKeyMapper struct {
	BaseURL string // default https://<account>.blob.core.windows.net
	Client  *http.Client
	Now     func() time.Time
}

func (m StorageKeyMapper) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	account := cred.Extra["account"]
	if account == "" {
		return nil, errors.New("azure-storage: account is required")
	}
	key, err := base64.StdEncoding.DecodeString(cred.Secret)
	if err != nil {
		return nil, errors.New("azure-storage: key is not base64")
	}
	base := strings.TrimRight(firstNonEmpty(m.BaseURL, "https://"+account+".blob.core.windows.net"), "/")
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	am := detectors.NewAccessMap("azure-storage")
	am.Identity = detectors.AccessIdentity{ID: account, Name: account, Type: "storage_account_key", Account: account}
	// A shared key grants full data-plane and key-management-equivalent
	// access to every service of the account.
	am.Privileged = true
	am.Permissions = append(am.Permissions, "storage:*")
	marker := ""
	for page := 0; page < 20; page++ {
		q := url.Values{"comp": {"list"}, "maxresults": {"5000"}}
		if marker != "" {
			q.Set("marker", marker)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/?"+q.Encode(), nil)
		if err != nil {
			return nil, err
		}
		sign(req, account, key, now())
		var out listContainers
		err = doXML(httpx.Client(m.Client), req, &out)
		if err != nil {
			if page == 0 {
				return nil, fmt.Errorf("azure-storage: list containers: %w", err)
			}
			am.Limitations = append(am.Limitations, "containers: "+err.Error())
			break
		}
		for _, c := range out.Containers {
			am.Resources = append(am.Resources, detectors.AccessResource{Type: "blob_container", Name: c, Permissions: []string{"read", "write", "delete"}})
		}
		if out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	am.Limitations = append(am.Limitations, "queues, tables and file shares not enumerated")
	return am, nil
}

// sign applies Shared Key authorization for the Blob service.
func sign(req *http.Request, account string, key []byte, t time.Time) {
	date := t.UTC().Format(http.TimeFormat)
	req.Header.Set("x-ms-date", date)
	req.Header.Set("x-ms-version", "2021-08-06")
	canonHeaders := "x-ms-date:" + date + "\nx-ms-version:2021-08-06\n"
	canonRes := "/" + account + req.URL.Path
	if canonRes == "/"+account {
		canonRes += "/"
	}
	q := req.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, strings.ToLower(k))
	}
	sortStrings(keys)
	for _, k := range keys {
		canonRes += "\n" + k + ":" + strings.Join(q[k], ",")
	}
	sts := req.Method + "\n\n\n\n\n\n\n\n\n\n\n\n" + canonHeaders + canonRes
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sts))
	req.Header.Set("Authorization", "SharedKey "+account+":"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
