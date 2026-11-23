package database

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// AdminRunner runs a read-only command against the admin database and
// decodes the reply into a generic document.
type AdminRunner interface {
	Run(ctx context.Context, cmd bson.D) (map[string]any, error)
	Close() error
}

// MongoDB maps a mongodb:// or mongodb+srv:// URI credential.
type MongoDB struct {
	Connect func(ctx context.Context, uri string) (AdminRunner, error)
}

type mongoRunner struct{ c *mongo.Client }

func (r mongoRunner) Run(ctx context.Context, cmd bson.D) (map[string]any, error) {
	var out map[string]any
	if err := r.c.Database("admin").RunCommand(ctx, cmd, options.RunCmd().SetReadPreference(readpref.PrimaryPreferred())).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r mongoRunner) Close() error { return r.c.Disconnect(context.Background()) }

func dialMongo(_ context.Context, uri string) (AdminRunner, error) {
	o := options.Client().ApplyURI(uri).SetConnectTimeout(ConnectTimeout).SetServerSelectionTimeout(ConnectTimeout).
		SetAppName("pleno-dlp-blast-radius").SetRetryWrites(false).SetMaxPoolSize(1)
	c, err := mongo.Connect(o)
	if err != nil {
		return nil, redactErr(err, uri)
	}
	return mongoRunner{c}, nil
}

var mongoPrivilegedRoles = []string{"root", "userAdminAnyDatabase", "dbAdminAnyDatabase", "readWriteAnyDatabase", "clusterAdmin", "atlasAdmin", "userAdmin", "dbOwner", "restore", "__system"}

// MapAccess implements detectors.AccessMapper. cred.Secret is the URI.
func (m MongoDB) MapAccess(ctx context.Context, cred detectors.AccessCredential) (*detectors.AccessMap, error) {
	if _, err := checkURI(cred.Secret, "mongodb", "mongodb+srv"); err != nil {
		return nil, fmt.Errorf("mongodb: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, QueryTimeout)
	defer cancel()
	connect := m.Connect
	if connect == nil {
		connect = dialMongo
	}
	c, err := connect(ctx, cred.Secret)
	if err != nil {
		return nil, fmt.Errorf("mongodb: connect: %w", err)
	}
	defer c.Close()
	st, err := c.Run(ctx, bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}})
	if err != nil {
		return nil, fmt.Errorf("mongodb: connectionStatus: %w", redactErr(err, cred.Secret))
	}
	am := detectors.NewAccessMap("mongodb")
	info, _ := st["authInfo"].(map[string]any)
	users := asSlice(info["authenticatedUsers"])
	if len(users) == 0 {
		return nil, fmt.Errorf("mongodb: connection is not authenticated")
	}
	u, _ := users[0].(map[string]any)
	am.Identity = detectors.AccessIdentity{ID: fmt.Sprint(u["db"]) + "." + fmt.Sprint(u["user"]), Name: fmt.Sprint(u["user"]), Type: "user", Account: fmt.Sprint(u["db"])}
	for _, r := range asSlice(info["authenticatedUserRoles"]) {
		rm, _ := r.(map[string]any)
		role, db := fmt.Sprint(rm["role"]), fmt.Sprint(rm["db"])
		am.Permissions = append(am.Permissions, role+"@"+db)
		am.Resources = append(am.Resources, detectors.AccessResource{Type: "role", Name: role + "@" + db, Permissions: []string{role}})
		if slices.Contains(mongoPrivilegedRoles, role) {
			am.Privileged = true
		}
	}
	dbs, err := c.Run(ctx, bson.D{{Key: "listDatabases", Value: 1}, {Key: "nameOnly", Value: true}, {Key: "authorizedDatabases", Value: true}})
	if err != nil {
		am.Limitations = append(am.Limitations, "databases: "+redactErr(err, cred.Secret).Error())
	}
	list := asSlice(dbs["databases"])
	if len(list) > MaxDatabases {
		list = list[:MaxDatabases]
		am.Limitations = append(am.Limitations, fmt.Sprintf("database listing capped at %d", MaxDatabases))
	}
	for _, d := range list {
		dm, _ := d.(map[string]any)
		if name := fmt.Sprint(dm["name"]); name != "" && !strings.EqualFold(name, "<nil>") {
			am.Resources = append(am.Resources, detectors.AccessResource{Type: "database", Name: name})
		}
	}
	am.Limitations = append(am.Limitations, "collection-level privileges are summarized by role, not enumerated")
	return am, nil
}

func asSlice(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case bson.A:
		return []any(t)
	}
	return nil
}
