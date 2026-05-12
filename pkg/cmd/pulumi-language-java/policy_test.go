package main

import (
	"os"
	"path/filepath"
	"testing"

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
