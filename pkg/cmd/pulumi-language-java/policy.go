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
	"time"

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

// hasGradleProject returns true iff the directory contains a Gradle build
// file (Groovy or Kotlin DSL).
func hasGradleProject(dir string) bool {
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// buildGradlePolicyExecArgs returns the gradle command line that runs the
// user's policy pack via a custom 'pulumiPolicyRun' task. The task is
// injected via an init script (see writePolicyInitScript) so users don't
// have to edit their build.gradle.kts.
func buildGradlePolicyExecArgs(projectDir, userEntrypoint string) []string {
	return []string{
		"--quiet",
		"--console=plain",
		"-p", projectDir,
		"-PpulumiPolicyMain=" + userEntrypoint,
		// pulumiPolicyRun is provided by the init script; see runPolicyPack.
		"pulumiPolicyRun",
	}
}

// writePolicyInitScript writes a Gradle init script that injects a
// 'pulumiPolicyRun' task into the user's project. The task uses the JavaExec
// type to run com.pulumi.policy.internal.PolicyMain with the user-supplied
// entrypoint class. The script is written to a system temp directory so that
// it is never left inside the user's project tree.
func writePolicyInitScript(_ string) (string, error) {
	content := `
allprojects {
    afterEvaluate { project ->
        if (project.plugins.hasPlugin('java') || project.plugins.hasPlugin('java-library')) {
            project.tasks.register('pulumiPolicyRun', JavaExec) {
                group = 'pulumi'
                description = 'Run the Pulumi policy pack via PolicyMain.'
                mainClass = 'com.pulumi.policy.internal.PolicyMain'
                args = [project.findProperty('pulumiPolicyMain') ?: '']
                classpath = project.sourceSets.main.runtimeClasspath
                standardOutput = System.out
                errorOutput = System.err
            }
        }
    }
}
`
	f, err := os.CreateTemp("", "pulumi-policy-init-*.gradle")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	return f.Name(), nil
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

const buildMarkerName = ".pulumi-policy-build-marker"

// needsRebuild returns true iff the policy pack at dir needs a fresh build.
// It is true when the build marker is missing, or when any source file
// (under src/, plus pom.xml or build.gradle{,.kts} at dir root) has been
// modified more recently than the marker.
func needsRebuild(dir string) (bool, error) {
	markerPath := filepath.Join(dir, buildMarkerName)
	markerInfo, err := os.Stat(markerPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, err
	}
	markerMtime := markerInfo.ModTime()

	// Check pom.xml / build.gradle(.kts) at dir root.
	for _, name := range []string{"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if info.ModTime().After(markerMtime) {
			return true, nil
		}
	}

	// Walk src/ for any newer file.
	srcDir := filepath.Join(dir, "src")
	stale := false
	walkErr := filepath.Walk(srcDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		if info.ModTime().After(markerMtime) {
			stale = true
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, os.ErrNotExist) {
		return false, walkErr
	}
	return stale, nil
}

// touchBuildMarker creates or refreshes the marker file at dir/.pulumi-policy-build-marker
// to record a successful build.
func touchBuildMarker(dir string) error {
	markerPath := filepath.Join(dir, buildMarkerName)
	f, err := os.OpenFile(markerPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Ensure mtime is now even if the file already existed.
	now := time.Now()
	return os.Chtimes(markerPath, now, now)
}
