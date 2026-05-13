//go:build policy_integration

// Run with: go test -tags policy_integration ./pkg/cmd/pulumi-language-java -run TestPolicyMode_BasicMaven -v
// Requires: mvn on PATH, JDK 11+, and com.pulumi:pulumi-policy:0.1.0-SNAPSHOT
// installed in the local Maven repo (cd ../../pulumi-policy/sdk/java && mvn install).

package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
)

// startInProcessLanguageHost boots a gRPC server hosting the language plugin
// on a random local port. Returns the client + a cleanup func.
func startInProcessLanguageHost(t *testing.T) (pulumirpc.LanguageRuntimeClient, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	host := newLanguageHost("" /*engineAddress*/, "" /*tracing*/, "" /*otelEndpoint*/)
	pulumirpc.RegisterLanguageRuntimeServer(srv, host)

	serverDone := make(chan struct{})
	go func() {
		_ = srv.Serve(listener)
		close(serverDone)
	}()

	conn, err := grpc.NewClient(listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	cleanup := func() {
		_ = conn.Close()
		// Use Stop (not GracefulStop) because the RunPlugin RPC runs until the
		// policy-pack subprocess exits; GracefulStop would block indefinitely
		// waiting for a long-lived streaming RPC to finish.
		srv.Stop()
		<-serverDone
		_ = listener.Close()
	}
	return pulumirpc.NewLanguageRuntimeClient(conn), cleanup
}

// runPluginAndCollectPort drives RunPlugin against the given dir and reads
// streamed stdout until it finds the gRPC port line printed by
// PolicyPack.run's handshake. Returns the parsed port, the accumulated
// stdout (useful for debugging on failure), and any stream-level error.
func runPluginAndCollectPort(t *testing.T, ctx context.Context,
	client pulumirpc.LanguageRuntimeClient, fixtureDir string,
) (int, []byte, error) {
	t.Helper()
	stream, err := client.RunPlugin(ctx, &pulumirpc.RunPluginRequest{
		Pwd:  fixtureDir,
		Info: &pulumirpc.ProgramInfo{ProgramDirectory: fixtureDir, EntryPoint: "."},
	})
	if err != nil {
		return 0, nil, err
	}

	portRegex := regexp.MustCompile(`(?m)^\s*(\d{2,5})\s*$`)
	var buf []byte
	for {
		resp, rerr := stream.Recv()
		if rerr != nil {
			return 0, buf, rerr
		}
		if out := resp.GetStdout(); len(out) > 0 {
			buf = append(buf, out...)
			if m := portRegex.FindSubmatch(buf); m != nil {
				port, perr := strconv.Atoi(string(m[1]))
				if perr != nil {
					return 0, buf, perr
				}
				return port, buf, nil
			}
		}
	}
}

func TestPolicyMode_BasicMaven(t *testing.T) {
	fixtureDir, err := filepath.Abs("testdata/policy-packs/basic-maven")
	require.NoError(t, err)

	client, cleanup := startInProcessLanguageHost(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	type portResult struct {
		port int
		buf  []byte
		err  error
	}
	portCh := make(chan portResult, 1)
	go func() {
		p, b, e := runPluginAndCollectPort(t, ctx, client, fixtureDir)
		portCh <- portResult{p, b, e}
	}()

	var res portResult
	select {
	case res = <-portCh:
	case <-time.After(90 * time.Second):
		t.Fatal("timed out waiting for port handshake from policy pack subprocess")
	}
	require.NoError(t, res.err, "RunPlugin stream error; stdout so far: %q", res.buf)
	require.NotZero(t, res.port, "no port found in stdout: %q", res.buf)

	// Connect to the AnalyzerServer the policy pack started.
	analyzerConn, err := grpc.NewClient(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(res.port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer analyzerConn.Close()

	analyzer := pulumirpc.NewAnalyzerClient(analyzerConn)

	info, err := analyzer.GetAnalyzerInfo(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "basic-maven-test-pack", info.GetName())
	assert.Len(t, info.GetPolicies(), 1)

	// Drive one Analyze with a violating S3 bucket.
	props, err := structpb.NewStruct(map[string]any{
		"acl": "public-read",
	})
	require.NoError(t, err)

	resp, err := analyzer.Analyze(ctx, &pulumirpc.AnalyzeRequest{
		Urn:        "urn:pulumi:dev::p::aws:s3/bucket:Bucket::b",
		Type:       "aws:s3/bucket:Bucket",
		Name:       "b",
		Properties: props,
	})
	require.NoError(t, err)
	require.Len(t, resp.GetDiagnostics(), 1)
	assert.Equal(t, "no-public-s3", resp.GetDiagnostics()[0].GetPolicyName())
	assert.Equal(t, "basic-maven-test-pack", resp.GetDiagnostics()[0].GetPolicyPackName())

	// Tell the analyzer to wind down (best-effort; cleanup kills the language
	// host which kills the policy pack subprocess).
	_, _ = analyzer.Cancel(ctx, &emptypb.Empty{})
}

// runPluginAndDrain drives RunPlugin against fixtureDir and reads stream
// chunks until EOF or first error. Returns accumulated stdout and the
// terminal stream error (nil on EOF, a gRPC error otherwise).
func runPluginAndDrain(t *testing.T, ctx context.Context,
	client pulumirpc.LanguageRuntimeClient, fixtureDir string,
) ([]byte, error) {
	t.Helper()
	stream, err := client.RunPlugin(ctx, &pulumirpc.RunPluginRequest{
		Pwd:  fixtureDir,
		Info: &pulumirpc.ProgramInfo{ProgramDirectory: fixtureDir, EntryPoint: "."},
	})
	if err != nil {
		return nil, err
	}
	var buf []byte
	for {
		resp, rerr := stream.Recv()
		if rerr != nil {
			if rerr.Error() == "EOF" {
				return buf, nil
			}
			return buf, rerr
		}
		if out := resp.GetStdout(); len(out) > 0 {
			buf = append(buf, out...)
		}
		if out := resp.GetStderr(); len(out) > 0 {
			buf = append(buf, out...)
		}
	}
}

func TestPolicyMode_MissingMainErrors(t *testing.T) {
	fixtureDir, err := filepath.Abs("testdata/policy-packs/missing-main")
	require.NoError(t, err)

	client, cleanup := startInProcessLanguageHost(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, streamErr := runPluginAndDrain(t, ctx, client, fixtureDir)
	require.Error(t, streamErr)
	assert.Contains(t, streamErr.Error(), "options.main")
}

func TestPolicyMode_MissingPomErrors(t *testing.T) {
	fixtureDir, err := filepath.Abs("testdata/policy-packs/no-pom")
	require.NoError(t, err)

	client, cleanup := startInProcessLanguageHost(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, streamErr := runPluginAndDrain(t, ctx, client, fixtureDir)
	require.Error(t, streamErr)
	assert.Contains(t, streamErr.Error(), "pom.xml")
}

func TestPolicyMode_BuildCacheSkipsRebuild(t *testing.T) {
	if _, err := exec.LookPath("mvn"); err != nil {
		t.Skip("mvn not on PATH; skipping cache test")
	}

	fixtureDir, err := filepath.Abs("testdata/policy-packs/basic-maven")
	require.NoError(t, err)
	// Remove any leftover marker from a prior run to ensure a cold start.
	_ = os.Remove(filepath.Join(fixtureDir, ".pulumi-policy-build-marker"))
	defer os.Remove(filepath.Join(fixtureDir, ".pulumi-policy-build-marker"))

	run := func(timeout time.Duration) time.Duration {
		client, cleanup := startInProcessLanguageHost(t)
		defer cleanup()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		start := time.Now()
		port, buf, streamErr := runPluginAndCollectPort(t, ctx, client, fixtureDir)
		require.NoError(t, streamErr, "RunPlugin stream error; stdout so far: %q", buf)
		require.NotZero(t, port, "no port found in stdout: %q", buf)
		// Cancel quickly; we only care about the build/handshake time.
		conn, err := grpc.NewClient(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		defer conn.Close()
		analyzer := pulumirpc.NewAnalyzerClient(conn)
		_, _ = analyzer.Cancel(ctx, &emptypb.Empty{})
		return time.Since(start)
	}

	cold := run(120 * time.Second)
	t.Logf("cold run: %v", cold)
	require.FileExists(t, filepath.Join(fixtureDir, ".pulumi-policy-build-marker"),
		"marker should exist after the first successful run")

	warm := run(60 * time.Second)
	t.Logf("warm run: %v", warm)

	// The warm run should be at least 30% faster. This is a loose bound to
	// avoid flakiness in CI; the real signal is in the log message above.
	require.Less(t, warm, cold*7/10,
		"warm run (%v) should be substantially faster than cold (%v) when build cache hits",
		warm, cold)
}

func TestPolicyMode_BasicGradle(t *testing.T) {
	if _, err := exec.LookPath("gradle"); err != nil {
		t.Skip("gradle not on PATH; skipping basic-gradle policy mode test")
	}

	fixtureDir, err := filepath.Abs("testdata/policy-packs/basic-gradle")
	require.NoError(t, err)

	client, cleanup := startInProcessLanguageHost(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	type portResult struct {
		port int
		buf  []byte
		err  error
	}
	portCh := make(chan portResult, 1)
	go func() {
		p, b, e := runPluginAndCollectPort(t, ctx, client, fixtureDir)
		portCh <- portResult{p, b, e}
	}()

	var res portResult
	select {
	case res = <-portCh:
	case <-time.After(150 * time.Second):
		t.Fatal("timed out waiting for port handshake from gradle policy pack")
	}
	require.NoError(t, res.err, "RunPlugin stream error; output so far: %q", res.buf)
	require.NotZero(t, res.port)

	analyzerConn, err := grpc.NewClient(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(res.port)),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer analyzerConn.Close()

	analyzer := pulumirpc.NewAnalyzerClient(analyzerConn)
	info, err := analyzer.GetAnalyzerInfo(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "sample-pack", info.GetName())

	_, _ = analyzer.Cancel(ctx, &emptypb.Empty{})
}
