package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type composeFile struct {
	Services map[string]struct {
		Ports       []string   `yaml:"ports"`
		Environment envEntries `yaml:"environment"`
	} `yaml:"services"`
}

// envEntries accepts Compose's two environment forms (list of KEY=VALUE, or
// a map) and normalises both to KEY=VALUE strings.
type envEntries []string

func (e *envEntries) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.SequenceNode:
		var list []string
		if err := n.Decode(&list); err != nil {
			return err
		}
		*e = list
	case yaml.MappingNode:
		var m map[string]string
		if err := n.Decode(&m); err != nil {
			return err
		}
		for k, v := range m {
			*e = append(*e, k+"="+v)
		}
	}
	return nil
}

func loadCompose(t *testing.T, rel string) composeFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", rel))
	if err != nil {
		t.Fatal(err)
	}
	var cf composeFile
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return cf
}

// TestCompose_DefaultStacksPublishToLoopbackOnly pins the deployment
// boundary the console's pairing (#537) does not provide: the data-plane API
// is development-open without TALON_ADMIN_KEY, so the default and demo
// Compose stacks publish every port to the host's loopback only. Console
// authentication must never read as "the installation is secured" while
// the API faces the network.
func TestCompose_DefaultStacksPublishToLoopbackOnly(t *testing.T) {
	for _, rel := range []string{"docker-compose.yml", "examples/docker-compose/docker-compose.yml"} {
		cf := loadCompose(t, rel)
		if len(cf.Services) == 0 {
			t.Fatalf("%s: no services parsed", rel)
		}
		if _, ok := cf.Services["talon-ui"]; !ok {
			t.Errorf("%s: the console service talon-ui must be part of the default stack (#536)", rel)
		}
		for name, svc := range cf.Services {
			for _, port := range svc.Ports {
				if !strings.HasPrefix(port, "127.0.0.1:") {
					t.Errorf("%s: service %s publishes %q to all interfaces; bind it to 127.0.0.1 (set TALON_ADMIN_KEY and change the binding deliberately to expose it)", rel, name, port)
				}
			}
		}
	}
}

// TestCompose_ProductionStackRequiresAdminKey: the production stack publishes
// the API on every interface, so Compose must refuse to start without
// TALON_ADMIN_KEY (the ${VAR:?message} form fails the whole `up`).
func TestCompose_ProductionStackRequiresAdminKey(t *testing.T) {
	cf := loadCompose(t, "deploy/docker-compose/full.yml")
	talon, ok := cf.Services["talon"]
	if !ok {
		t.Fatal("full.yml: talon service missing")
	}
	exposed := false
	for _, p := range talon.Ports {
		if !strings.HasPrefix(p, "127.0.0.1:") {
			exposed = true
		}
	}
	if !exposed {
		return // loopback-only stacks need no key by this rule
	}
	for _, env := range talon.Environment {
		if strings.HasPrefix(env, "TALON_ADMIN_KEY=${TALON_ADMIN_KEY:?") {
			return
		}
	}
	t.Fatalf("full.yml publishes the API on all interfaces but does not require TALON_ADMIN_KEY (expected TALON_ADMIN_KEY=${TALON_ADMIN_KEY:?...}); env: %v", talon.Environment)
}
