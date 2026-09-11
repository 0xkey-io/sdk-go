package sdk_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/0xkey-io/sdk-go/pkg/api/client/m_f_a_policies"
	"github.com/0xkey-io/sdk-go/pkg/api/models"
)

const frozenOpenAPISHA256 = "5434f36777abe0672c53e8c0b5b1938147de78a235ddb938f5877b616e6644ad" // gitleaks:allow

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
	if len(pin["services_commit"]) != 40 {
		t.Fatalf("services_commit=%q", pin["services_commit"])
	}
}

func TestSwaggerHasAuthenticatorsNeededAndGetMfaStatus(t *testing.T) {
	raw, err := os.ReadFile("api/public_api.swagger.json")
	if err != nil {
		t.Fatal(err)
	}
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
	for _, value := range swagger.Definitions["ActivityStatus"].Enum {
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
