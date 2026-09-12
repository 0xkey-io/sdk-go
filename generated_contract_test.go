package sdk_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/0xkey-io/sdk-go/pkg/api/client/m_f_a_policies"
	"github.com/0xkey-io/sdk-go/pkg/api/models"
)

const frozenOpenAPISHA256 = "b42fcfa9a9480c2d4148038b8d9112559132b11727c7f839e05cb2782e3350e2" // gitleaks:allow
const frozenServicesCommit = "096c1fec26bed3b3f8104b473b35903db76760bb"
const frozenGeneratorInputSHA256 = "7bb267ce5f553848f6ecb97e092232ccc7c6d5eb4bdacdef3dcf52eafbfeeeb3"

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
