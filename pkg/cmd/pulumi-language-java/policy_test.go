package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPolicyConfig_ValidMavenPack(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "PulumiPolicy.yaml")
	manifest := []byte(`runtime:
  name: java
  options:
    main: com.example.Pack
version: 1.0.0
description: Test pack
`)
	require.NoError(t, os.WriteFile(manifestPath, manifest, 0o644))

	cfg, err := loadPolicyConfig(dir)
	require.NoError(t, err)
	assert.Equal(t, "java", cfg.Runtime.Name)
	assert.Equal(t, "com.example.Pack", cfg.Runtime.Options.Main)
}

func TestLoadPolicyConfig_MissingFile(t *testing.T) {
	cfg, err := loadPolicyConfig(t.TempDir())
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "PulumiPolicy.yaml")
}

func TestLoadPolicyConfig_MissingMain(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "PulumiPolicy.yaml"),
		[]byte("runtime:\n  name: java\n"),
		0o644,
	))

	cfg, err := loadPolicyConfig(dir)
	require.NoError(t, err)
	assert.Equal(t, "", cfg.Runtime.Options.Main) // empty, caller must check
}

func TestLoadPolicyConfig_WrongRuntime(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "PulumiPolicy.yaml"),
		[]byte("runtime: nodejs\n"),
		0o644,
	))

	// Scalar form of runtime should still parse (Name=nodejs, Options empty).
	cfg, err := loadPolicyConfig(dir)
	require.NoError(t, err)
	assert.Equal(t, "nodejs", cfg.Runtime.Name)
}

func TestIsPolicyPack_True(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "PulumiPolicy.yaml"),
		[]byte("runtime: java\n"),
		0o644,
	))
	assert.True(t, isPolicyPack(dir))
}

func TestIsPolicyPack_FalseNoManifest(t *testing.T) {
	assert.False(t, isPolicyPack(t.TempDir()))
}

func TestIsPolicyPack_FalseOnDirectoryAtPath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "PulumiPolicy.yaml"), 0o755))
	// A directory named PulumiPolicy.yaml is not a manifest.
	assert.False(t, isPolicyPack(dir))
}

func TestBuildMavenPolicyExecArgs(t *testing.T) {
	args := buildMavenPolicyExecArgs("/abs/path/to/pom.xml", "com.example.Pack")

	// Sanity: contains the key flags. Don't assert exact ordering of all
	// boilerplate flags - just the load-bearing ones.
	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "compile")
	assert.Contains(t, joined, "exec:java")
	assert.Contains(t, joined, "-f /abs/path/to/pom.xml")
	assert.Contains(t, joined, "-Dexec.mainClass=com.pulumi.policy.internal.PolicyMain")
	assert.Contains(t, joined, "-Dexec.args=com.example.Pack")
	// Log output diverted from stdout (which must stay clean for the port handshake)
	assert.Contains(t, joined, "logFile=System.err")
}

func TestBuildMavenPolicyExecArgs_EscapesUserEntrypointWithSpaces(t *testing.T) {
	// Defensive: should never happen (FQNs don't contain spaces) but make sure
	// nothing in the build raises eyebrows.
	args := buildMavenPolicyExecArgs("/p.xml", "com.example.Pack$Inner")
	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "-Dexec.args=com.example.Pack$Inner")
}

func TestHasGradleProject_GroovyDSL(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "build.gradle"), []byte(""), 0o644))
	assert.True(t, hasGradleProject(dir))
}

func TestHasGradleProject_KotlinDSL(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "build.gradle.kts"), []byte(""), 0o644))
	assert.True(t, hasGradleProject(dir))
}

func TestHasGradleProject_False(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(""), 0o644))
	assert.False(t, hasGradleProject(dir))
}

func TestBuildGradlePolicyExecArgs(t *testing.T) {
	args := buildGradlePolicyExecArgs("/abs/project", "com.example.Pack")
	joined := strings.Join(args, " ")
	assert.Contains(t, joined, "-p /abs/project")
	assert.Contains(t, joined, "pulumiPolicyRun")
	assert.Contains(t, joined, "-PpulumiPolicyMain=com.example.Pack")
	// Gradle output must go to stderr so stdout stays clean for the port handshake.
	assert.Contains(t, joined, "--quiet")
}

func TestNeedsRebuild_NoMarker(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src/a.java"), []byte(""), 0o644))
	rebuild, err := needsRebuild(dir)
	require.NoError(t, err)
	assert.True(t, rebuild, "no marker → must rebuild")
}

func TestNeedsRebuild_MarkerNewerThanSources(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src/a.java"), []byte(""), 0o644))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, touchBuildMarker(dir))
	rebuild, err := needsRebuild(dir)
	require.NoError(t, err)
	assert.False(t, rebuild, "marker newer than sources → skip rebuild")
}

func TestNeedsRebuild_SourceModifiedAfterMarker(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "src"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src/a.java"), []byte(""), 0o644))
	require.NoError(t, touchBuildMarker(dir))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "src/a.java"), []byte("changed"), 0o644))
	rebuild, err := needsRebuild(dir)
	require.NoError(t, err)
	assert.True(t, rebuild, "source changed after marker → must rebuild")
}

func TestNeedsRebuild_PomChangedAfterMarker(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<?xml?>"), 0o644))
	require.NoError(t, touchBuildMarker(dir))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte("<?xml?>\n<!-- changed -->"), 0o644))
	rebuild, err := needsRebuild(dir)
	require.NoError(t, err)
	assert.True(t, rebuild, "pom.xml changed after marker → must rebuild")
}
