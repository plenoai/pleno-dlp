//go:build detector_unit

package kafka

import (
	"context"
	"strings"
	"testing"
)

func TestFromData_PropertyStyle(t *testing.T) {
	body := strings.Join([]string{
		"bootstrap.servers=kafka.example.com:9093",
		"sasl.username=alice",
		"sasl.password=hunter2",
	}, "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "hunter2" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != "alice" {
		t.Fatalf("username: %q", res[0].RawV2)
	}
	if got := res[0].ExtraData["bootstrap_servers"]; got != "kafka.example.com:9093" {
		t.Fatalf("bootstrap: %q", got)
	}
}

func TestFromData_JAASStyle(t *testing.T) {
	body := `sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="bob" password="s3cr3t";`
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "s3cr3t" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != "bob" {
		t.Fatalf("username: %q", res[0].RawV2)
	}
}

func TestFromData_NoCredentials(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("bootstrap.servers=kafka:9092"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// FP fixture 1: a Kafka JAAS block alongside an unrelated Spring datasource
// password rendered as password="…" elsewhere in the same chunk. Only the
// JAAS-clause password must be emitted; the datasource value must not.
func TestFromData_JAASStyle_IgnoresUnrelatedDatasource(t *testing.T) {
	body := strings.Join([]string{
		`spring.datasource.username=dbuser`,
		`spring.datasource.password="hunter2dbValueX9"`,
		`spring.kafka.properties.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="bob" password="Zk8vQ2pLmN4w";`,
	}, "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "Zk8vQ2pLmN4w" {
		t.Fatalf("expected kafka jaas password, got %q", res[0].Raw)
	}
	if string(res[0].RawV2) != "bob" {
		t.Fatalf("username: %q", res[0].RawV2)
	}
}

// FP fixture 2: an XML config where a JDBC bean carries username/password and a
// separate bean references PlainLoginModule with no credentials in its clause.
// The JDBC password must not be attributed to Kafka.
func TestFromData_JAASStyle_IgnoresJDBCBean(t *testing.T) {
	body := strings.Join([]string{
		`<bean id="ds"><property name="username" value="svc"/>`,
		`<property name="password" value="dbpw"/></bean>`,
		`<bean id="jdbc">username="svc" password="jdbcSecretValue42"</bean>`,
		`<bean id="kafka">org.apache.kafka.common.security.plain.PlainLoginModule required;</bean>`,
	}, "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 (JDBC password outside JAAS clause), got %d: %+v", len(res), res)
	}
}

// FP fixture 3: a templated interpolation token inside a real JAAS clause must
// be suppressed (it is not a live secret).
func TestFromData_JAASStyle_SuppressesPlaceholder(t *testing.T) {
	body := `sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="bob" password="${KAFKA_SASL_PASSWORD}";`
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 (templated placeholder), got %d: %+v", len(res), res)
	}
}

// True-positive: the original JAAS shape is still detected after hardening.
func TestFromData_JAASStyle_StillDetected(t *testing.T) {
	body := `sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="bob" password="s3cr3tP4ss";`
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "s3cr3tP4ss" {
		t.Fatalf("password: %q", res[0].Raw)
	}
}
