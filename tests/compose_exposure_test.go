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

// TestCompose_PublishedImagePathNeverBuilds pins the customer's
// published-image path of the demo stack (#533): Compose answers a failed
// pull by building from source whenever a service has a build section, so
// the published path is an override that removes the build sections, names
// one required image for both Talon services, pulls by default and publishes
// nothing new. The base file stays the contributor's source build and reads
// no image variable, so naming an image without the override can never look
// like a published-image run.
func TestCompose_PublishedImagePathNeverBuilds(t *testing.T) {
	type service struct {
		Build      yaml.Node `yaml:"build"`
		Image      string    `yaml:"image"`
		PullPolicy string    `yaml:"pull_policy"`
		Ports      []string  `yaml:"ports"`
	}
	load := func(rel string) map[string]service {
		raw, err := os.ReadFile(filepath.Join("..", rel))
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Services map[string]service `yaml:"services"`
		}
		if err := yaml.Unmarshal(raw, &f); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		return f.Services
	}
	base := load("examples/docker-compose/docker-compose.yml")
	pub := load("examples/docker-compose/docker-compose.published.yml")
	if len(pub) != 2 {
		t.Fatalf("the override must touch exactly talon and talon-ui, got %d services", len(pub))
	}
	for _, name := range []string{"talon", "talon-ui"} {
		b, p := base[name], pub[name]
		if b.Build.Kind == 0 || strings.Contains(b.Image, "$") || b.PullPolicy != "" {
			t.Errorf("base %s must build from source and read no image variable (image %q, pull_policy %q)", name, b.Image, b.PullPolicy)
		}
		if p.Build.Tag != "!reset" || p.Build.Value != "null" {
			t.Errorf("published %s must remove the build section with `build: !reset null` (tag %q, value %q)", name, p.Build.Tag, p.Build.Value)
		}
		if !strings.HasPrefix(p.Image, "${TALON_IMAGE:?") {
			t.Errorf("published %s must require TALON_IMAGE with no default, got %q", name, p.Image)
		}
		if p.PullPolicy != "${TALON_PULL_POLICY:-always}" {
			t.Errorf("published %s must pull by default, got %q", name, p.PullPolicy)
		}
		if len(p.Ports) != 0 {
			t.Errorf("published %s must not change port publication", name)
		}
	}
	if pub["talon"].Image != pub["talon-ui"].Image {
		t.Error("data plane and console must run the same image reference")
	}
}
