// Copyright 2026, Pulumi Corporation.  All rights reserved.

// Policy-mode helpers for pulumi-language-java. When the language plugin's
// RunPlugin RPC targets a directory containing PulumiPolicy.yaml, the
// directory is a Pulumi policy pack rather than a Pulumi program. The
// helpers in this file detect that case, parse the manifest, and build
// the Maven exec args needed to launch the user's pack via
// com.pulumi.policy.internal.PolicyMain.

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const manifestFileName = "PulumiPolicy.yaml"

// PolicyConfig is the subset of PulumiPolicy.yaml the language plugin reads.
// `runtime` may appear as either a scalar (`runtime: java`) or a mapping
// (`runtime: {name: java, options: {...}}`). The custom UnmarshalYAML on
// policyRuntime handles both.
type PolicyConfig struct {
	Runtime policyRuntime `yaml:"runtime"`
}

type policyRuntime struct {
	Name    string        `yaml:"name"`
	Options policyOptions `yaml:"options"`
}

type policyOptions struct {
	// Main is the fully qualified class name of the user's policy pack
	// entrypoint - the class containing `public static void main(String[])`
	// that calls PolicyPack.run(...). Required for Java policy packs.
	Main string `yaml:"main"`
}

// UnmarshalYAML handles both the scalar and mapping forms of `runtime:`.
func (r *policyRuntime) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		r.Name = node.Value
		return nil
	case yaml.MappingNode:
		// Decode into a clone of the struct to avoid recursion.
		type rawRuntime struct {
			Name    string        `yaml:"name"`
			Options policyOptions `yaml:"options"`
		}
		var raw rawRuntime
		if err := node.Decode(&raw); err != nil {
			return err
		}
		r.Name = raw.Name
		r.Options = raw.Options
		return nil
	default:
		return fmt.Errorf("runtime: unexpected YAML node kind %d", node.Kind)
	}
}

// loadPolicyConfig reads and parses PulumiPolicy.yaml at the given directory.
// Returns an error if the file is missing or malformed. The presence of the
// file is the primary signal for policy-mode detection; callers that want a
// boolean check should use isPolicyPack instead.
func loadPolicyConfig(dir string) (*PolicyConfig, error) {
	path := filepath.Join(dir, manifestFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no PulumiPolicy.yaml at %s", dir)
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg PolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}

// isPolicyPack returns true iff the directory contains a regular
// PulumiPolicy.yaml file. This is the primary signal the language plugin
// uses to switch RunPlugin into policy mode.
func isPolicyPack(dir string) bool {
	info, err := os.Stat(filepath.Join(dir, manifestFileName))
	return err == nil && info.Mode().IsRegular()
}

// buildMavenPolicyExecArgs returns the mvn command-line that builds the user's
// policy-pack project and invokes PolicyMain with the user's entrypoint FQN.
// The first stdout line from the resulting subprocess is the gRPC port the
// AnalyzerServer started on - the rest of the language plugin's RunPlugin
// flow handles port-line forwarding to the engine.
//
// Mirrors the layout used by executor_maven.go:73-80 for normal programs,
// but overrides exec.mainClass.
func buildMavenPolicyExecArgs(pomXMLPath, userEntrypoint string) []string {
	return []string{
		// only output warning or higher to reduce noise
		"-Dorg.slf4j.simpleLogger.defaultLogLevel=warn",
		// keep stdout clean for the port handshake; mvn's normal output goes to stderr
		"-Dorg.slf4j.simpleLogger.logFile=System.err",
		"--no-transfer-progress",
		"compile",
		"exec:java",
		"-f", pomXMLPath,
		"-Dexec.mainClass=com.pulumi.policy.internal.PolicyMain",
		fmt.Sprintf("-Dexec.args=%s", userEntrypoint),
	}
}
