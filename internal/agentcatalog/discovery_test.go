package agentcatalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeAgentFile writes a schema-valid agent.talon.yaml under dir/sub.
func writeAgentFile(t *testing.T, dir, sub, name, secretName string) string {
	t.Helper()
	d := filepath.Join(dir, filepath.FromSlash(sub))
	require.NoError(t, os.MkdirAll(d, 0o755))
	content := "agent:\n  name: " + name + "\n  version: \"1.0.0\"\n"
	if secretName != "" {
		content += "  key:\n    secret_name: " + secretName + "\n"
	}
	content += "policies:\n  cost_limits:\n    daily: 10\n"
	path := filepath.Join(d, AgentConfigFilename)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func writeRawFile(t *testing.T, dir, sub, filename, content string) string {
	t.Helper()
	d := filepath.Join(dir, filepath.FromSlash(sub))
	require.NoError(t, os.MkdirAll(d, 0o755))
	path := filepath.Join(d, filename)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestDiscoverAgents_NestedScanExactFilename(t *testing.T) {
	dir := t.TempDir()
	pathA := writeAgentFile(t, dir, "customer-support", "customer-support", "cs-key")
	pathB := writeAgentFile(t, dir, "teams/coding/prod", "coding", "coding-key")
	// Not agents: wrong filename, non-yaml, hidden directory.
	writeRawFile(t, dir, "customer-support", "foo.talon.yaml", "agent:\n  name: not-an-agent\n  version: \"1.0.0\"\npolicies: {}\n")
	writeRawFile(t, dir, "notes", "README.md", "# notes\n")
	writeRawFile(t, dir, ".archive/old", AgentConfigFilename, "agent:\n  name: archived\n  version: \"1.0.0\"\npolicies: {}\n")

	scan, err := DiscoverAgents(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, scan.Agents, 2)
	assert.Empty(t, scan.Issues)
	assert.Equal(t, "customer-support", scan.Agents[0].Name)
	assert.Equal(t, pathA, scan.Agents[0].Path)
	assert.Equal(t, "coding", scan.Agents[1].Name)
	assert.Equal(t, pathB, scan.Agents[1].Path)
	assert.NotEmpty(t, scan.Agents[0].PolicyDigest, "canonical policy digest travels into the catalog")
	assert.True(t, scan.Agents[0].Enabled, "agents are on until #268 lands agent.enabled")

	loaded := scan.LoadedAgents()
	require.Len(t, loaded, 2)
	assert.Equal(t, "cs-key", loaded[0].KeySecretName, "gateway adaptation rides the shared bridge")
}

func TestDiscoverAgents_DuplicateNamesFailClosed(t *testing.T) {
	dir := t.TempDir()
	first := writeAgentFile(t, dir, "a", "support", "key-a")
	second := writeAgentFile(t, dir, "b", "support", "key-b")

	scan, err := DiscoverAgents(context.Background(), dir)
	require.Error(t, err, "duplicate agent.name rejects the scan")
	assert.Contains(t, err.Error(), "fail closed")
	// BOTH files fail closed (#267 review): neither produces a valid agent, so
	// nothing silently resolves the ambiguous name to whichever sorted first.
	require.Len(t, scan.Issues, 2)
	require.Empty(t, scan.Agents, "no valid CatalogAgent for a duplicated name")
	issuePaths := []string{scan.Issues[0].Path, scan.Issues[1].Path}
	assert.ElementsMatch(t, []string{first, second}, issuePaths)
	for _, iss := range scan.Issues {
		assert.Equal(t, IssueDuplicateName, iss.Status)
		assert.Contains(t, iss.Reason, "support", "the reason names the ambiguous agent")
	}
}

func TestDiscoverAgents_InvalidFileRejectsScanButSiblingsListed(t *testing.T) {
	dir := t.TempDir()
	writeAgentFile(t, dir, "good", "good-agent", "good-key")
	bad := writeRawFile(t, dir, "bad", AgentConfigFilename, "agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    daily: 1\n") // missing required name

	scan, err := DiscoverAgents(context.Background(), dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), bad)
	require.Len(t, scan.Files, 2, "every found file is reported")
	require.Len(t, scan.Agents, 1, "the valid sibling still parses")
	assert.Equal(t, "good-agent", scan.Agents[0].Name)
	require.Len(t, scan.Issues, 1)
	assert.Equal(t, IssueInvalidConfig, scan.Issues[0].Status)
	assert.Empty(t, scan.Issues[0].Agent, "no identity is synthesized from an invalid file")
}

func TestDiscoverAgents_UnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	writeRawFile(t, dir, "typo", AgentConfigFilename,
		"agent:\n  name: typo-agent\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    montly: 25\n")

	scan, err := DiscoverAgents(context.Background(), dir)
	require.Error(t, err, "a typo'd key silently dropping a control must fail the scan")
	require.Len(t, scan.Issues, 1)
	assert.Contains(t, scan.Issues[0].Reason, "montly")
}

func TestDiscoverAgents_EmptyAndMissingDir(t *testing.T) {
	dir := t.TempDir()
	scan, err := DiscoverAgents(context.Background(), dir)
	require.NoError(t, err, "an empty directory is not a scan error — callers enforce their minimums")
	assert.Empty(t, scan.Agents)
	assert.NotEmpty(t, scan.Digest, "even an empty scan has a generation identity")

	_, err = DiscoverAgents(context.Background(), filepath.Join(dir, "missing"))
	require.Error(t, err)

	filePath := writeAgentFile(t, dir, "x", "x", "")
	_, err = DiscoverAgents(context.Background(), filePath)
	require.Error(t, err, "agents_dir must be a directory")
}

func TestDiscoverAgents_DigestTracksContentIncludingInvalidFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeAgentFile(t, dir, "a", "agent-a", "key-a")
	bad := writeRawFile(t, dir, "b", AgentConfigFilename, "agent:\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    daily: 1\n")

	scan1, err1 := DiscoverAgents(ctx, dir)
	require.Error(t, err1)
	scan2, err2 := DiscoverAgents(ctx, dir)
	require.Error(t, err2)
	assert.Equal(t, scan1.Digest, scan2.Digest, "the digest is deterministic")

	// Fixing the broken file MUST change the digest — that is what lets the
	// reload loop (#269) notice the fix and retrigger a build.
	require.NoError(t, os.WriteFile(bad, []byte("agent:\n  name: agent-b\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    daily: 1\n"), 0o600))
	scan3, err3 := DiscoverAgents(ctx, dir)
	require.NoError(t, err3)
	assert.NotEqual(t, scan1.Digest, scan3.Digest)

	// Membership changes the digest too.
	writeAgentFile(t, dir, "c", "agent-c", "key-c")
	scan4, err4 := DiscoverAgents(ctx, dir)
	require.NoError(t, err4)
	assert.NotEqual(t, scan3.Digest, scan4.Digest)
}

func TestSourceScan_SingleFileParity(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := writeAgentFile(t, dir, "solo", "solo-agent", "solo-key")

	fromFile, err := Source{File: path}.Scan(ctx)
	require.NoError(t, err)
	require.Len(t, fromFile.Agents, 1)

	fromDir, err := Source{Dir: filepath.Join(dir, "solo")}.Scan(ctx)
	require.NoError(t, err)
	require.Len(t, fromDir.Agents, 1)

	// Same pipeline in both modes: identical agent identity out.
	assert.Equal(t, fromDir.Agents[0].Name, fromFile.Agents[0].Name)
	assert.Equal(t, fromDir.Agents[0].PolicyDigest, fromFile.Agents[0].PolicyDigest)
	assert.Equal(t, fromDir.Agents[0].LoadedAgent().KeySecretName, fromFile.Agents[0].LoadedAgent().KeySecretName)
}

func TestSourceScan_SingleFileStrictAndMissing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// The single-file mode applies the SAME strict unknown-key gate as the
	// directory scan — the two modes must not drift.
	typo := writeRawFile(t, dir, "t", AgentConfigFilename,
		"agent:\n  name: t\n  version: \"1.0.0\"\npolicies:\n  cost_limits:\n    montly: 1\n")
	_, err := Source{File: typo}.Scan(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "montly")

	_, err = Source{File: filepath.Join(dir, "absent.yaml")}.Scan(ctx)
	require.Error(t, err)

	_, err = Source{}.Scan(ctx)
	require.Error(t, err, "an empty source is a configuration error")
}

func TestSourceString(t *testing.T) {
	assert.Equal(t, "agents_dir ./agents", Source{Dir: "./agents"}.String())
	assert.Equal(t, "agent.talon.yaml", Source{File: "agent.talon.yaml"}.String())
}

func TestDiscoverAgents_ManyAgentsSortedByPath(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		writeAgentFile(t, dir, fmt.Sprintf("agents/%c", 'e'-i), fmt.Sprintf("agent-%c", 'e'-i), "")
	}
	scan, err := DiscoverAgents(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, scan.Agents, 5)
	for i := 1; i < len(scan.Files); i++ {
		assert.Less(t, scan.Files[i-1].Path, scan.Files[i].Path, "deterministic path order")
	}
}
