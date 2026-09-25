package sdk_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/0xkey-io/sdk-go/pkg/api/client/m_f_a_policies"
	"github.com/0xkey-io/sdk-go/pkg/api/models"
)

const frozenOpenAPISHA256 = "cca6a179db09bb9ea1d01deabd0b9e7122f4dbc1f27735efdcf433700aee42e2" // gitleaks:allow
const frozenServicesCommit = "0eb6eb86a2ddb875552e97a33880d2c1c1eb4e4e"
const frozenGeneratorInputSHA256 = "ce17ca2fc5f7356d61af1259ba76ecc836c37d8b5c78cadf29af6faf5c92dc96"

//nolint:gocyclo // One table-like contract assertion intentionally checks every pinned field.
func TestGeneratedMfaContractPin(t *testing.T) {
	raw, err := os.ReadFile("api/contract-pin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pin := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(strings.TrimSpace(strings.Split(line, "#")[0]), ":", 2)
		if len(parts) != 2 {
			continue
		}
		pin[strings.TrimSpace(parts[0])] = strings.Trim(strings.TrimSpace(parts[1]), `"`)
	}
	if pin["openapi_sha256"] != frozenOpenAPISHA256 {
		t.Fatalf("openapi_sha256=%s want %s", pin["openapi_sha256"], frozenOpenAPISHA256)
	}
	if pin["services_commit"] != frozenServicesCommit {
		t.Fatalf("services_commit=%q want %q", pin["services_commit"], frozenServicesCommit)
	}
	if pin["generator_input_sha256"] != frozenGeneratorInputSHA256 {
		t.Fatalf("generator_input_sha256=%q want %q", pin["generator_input_sha256"], frozenGeneratorInputSHA256)
	}
	generatorInput, err := os.ReadFile("api/public_api.swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(generatorInput)); got != frozenGeneratorInputSHA256 {
		t.Fatalf("generator input sha256=%s want %s", got, frozenGeneratorInputSHA256)
	}
	projection := exec.Command("./scripts/project-services-openapi.sh", "--check")
	if output, err := projection.CombinedOutput(); err != nil {
		t.Fatalf("compatibility projection is stale: %v\n%s", err, output)
	}
	swagger, err := os.ReadFile("api/services-public_api.swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(swagger)); got != frozenOpenAPISHA256 {
		t.Fatalf("generator input sha256=%s want %s", got, frozenOpenAPISHA256)
	}
}

func TestSwaggerHasAuthenticatorsNeededAndGetMfaStatus(t *testing.T) {
	raw, err := os.ReadFile("api/public_api.swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	assertSwaggerHasMfaContract(t, raw, "ActivityStatus")

	source, err := os.ReadFile("api/services-public_api.swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	assertSwaggerHasMfaContract(t, source, "v1ActivityStatus")
}

func assertSwaggerHasMfaContract(t *testing.T, raw []byte, statusDefinition string) {
	t.Helper()
	var swagger struct {
		Paths       map[string]json.RawMessage `json:"paths"`
		Definitions map[string]struct {
			Enum []string `json:"enum"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &swagger); err != nil {
		t.Fatal(err)
	}
	if _, ok := swagger.Paths["/public/v1/query/get_mfa_status"]; !ok {
		t.Fatal("missing /public/v1/query/get_mfa_status")
	}
	found := false
	for _, value := range swagger.Definitions[statusDefinition].Enum {
		if value == "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("ActivityStatus missing ACTIVITY_STATUS_AUTHENTICATORS_NEEDED")
	}
}

func TestGeneratedClientHasGetMfaStatus(t *testing.T) {
	if models.ActivityStatusAuthenticatorsNeeded != "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED" {
		t.Fatalf("got %s", models.ActivityStatusAuthenticatorsNeeded)
	}
	var api m_f_a_policies.ClientService
	_ = api
}

func TestGeneratedTurnkeyIdentityContract(t *testing.T) {
	credentialType := reflect.TypeOf(models.ExternalDataV1Credential{})
	if _, ok := credentialType.FieldByName("SessionProfileID"); !ok {
		t.Fatal("ExternalDataV1Credential missing SessionProfileID")
	}

	userType := reflect.TypeOf(models.User{})
	field, ok := userType.FieldByName("MfaPolicies")
	if !ok {
		t.Fatal("User missing required MfaPolicies")
	}
	if field.Tag.Get("json") != "mfaPolicies" {
		t.Fatalf("MfaPolicies json tag=%q want %q", field.Tag.Get("json"), "mfaPolicies")
	}

	for _, value := range models.AuthenticationTypeEnum {
		if value == "AUTHENTICATION_TYPE_UNSPECIFIED" {
			t.Fatal("AuthenticationType must not expose AUTHENTICATION_TYPE_UNSPECIFIED")
		}
	}
}

func TestGeneratedStampLoginIntentMarshalsSessionProfileID(t *testing.T) {
	publicKey := "04deadbeef"
	profileID := "session-profile-1"
	intent := models.StampLoginIntent{
		PublicKey:        &publicKey,
		SessionProfileID: profileID,
	}

	raw, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if got := payload["sessionProfileId"]; got != profileID {
		t.Fatalf("sessionProfileId=%v want %q", got, profileID)
	}
}
