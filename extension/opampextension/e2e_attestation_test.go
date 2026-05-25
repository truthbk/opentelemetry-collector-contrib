// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package opampextension

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server"
	servertypes "github.com/open-telemetry/opamp-go/server/types"
	"github.com/open-telemetry/opamp-go/signing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension/extensiontest"
)

// makeAttestationTestSigner generates an ephemeral ECDSA P-256 CA +
// leaf and returns (a) a LocalSigner for the OpAMP server and (b) the
// on-disk PEM path the extension's signing.ca_cert_file points at.
//
// Mirror of cmd/opampsupervisor/e2e_attestation_test.go::makeTestSigner;
// kept in sync with that helper.
func makeAttestationTestSigner(t *testing.T) (*signing.LocalSigner, string) {
	t.Helper()
	ca, caKey, err := signing.GenerateCA(signing.AlgorithmECDSAP256SHA256, signing.CertOptions{})
	require.NoError(t, err)
	leaf, leafKey, err := signing.GenerateLeaf(signing.AlgorithmECDSAP256SHA256, ca, caKey, signing.CertOptions{})
	require.NoError(t, err)
	signer, err := signing.NewLocalSigner(leafKey, []*x509.Certificate{leaf})
	require.NoError(t, err)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}),
		0o600))
	return signer, caPath
}

// extensionTestServer wraps an httptest-hosted OpAMP server that the
// extension's OpAMP client connects to via the standard WS endpoint.
type extensionTestServer struct {
	endpoint    string
	disconnects *atomic.Int32
	statusChan  chan *protobufs.RemoteConfigStatus
	connected   chan struct{}
	// negotiated closes after the first AgentToServer lands on the
	// server — meaning the server-side attestation negotiation is
	// complete and Send is safe to call (see opamp-go's
	// ErrSendBeforeNegotiated). Tests that need to push a server-
	// initiated message MUST wait on this signal first.
	negotiated chan struct{}
	send       func(*protobufs.ServerToAgent)
}

// newExtensionTestServer creates and starts an OpAMP server that
// signs outbound messages with signer (when non-nil). The extension
// is expected to connect with PayloadVerifier set so it observes
// SignedServerToAgent envelopes.
func newExtensionTestServer(t *testing.T, signer signing.Signer) *extensionTestServer {
	t.Helper()

	var (
		agentConn      atomic.Value
		isConnected    atomic.Bool
		didShutdown    atomic.Bool
		disconnects    atomic.Int32
		connectedOnce  atomic.Bool
		negotiatedOnce atomic.Bool
		statusChan     = make(chan *protobufs.RemoteConfigStatus, 8)
		connectedChan  = make(chan struct{}, 1)
		negotiatedChan = make(chan struct{})
	)

	callbacks := servertypes.ConnectionCallbacks{
		OnConnected: func(_ context.Context, conn servertypes.Connection) {
			if didShutdown.Load() {
				return
			}
			agentConn.Store(conn)
			isConnected.Store(true)
			if connectedOnce.CompareAndSwap(false, true) {
				connectedChan <- struct{}{}
			}
		},
		OnMessage: func(_ context.Context, _ servertypes.Connection, msg *protobufs.AgentToServer) *protobufs.ServerToAgent {
			// OnMessage firing implies the server's WS receive loop
			// has called markNegotiated, so subsequent Send calls
			// from the test goroutine won't trip ErrSendBeforeNegotiated.
			if negotiatedOnce.CompareAndSwap(false, true) {
				close(negotiatedChan)
			}
			if msg.RemoteConfigStatus != nil {
				select {
				case statusChan <- msg.RemoteConfigStatus:
				default:
				}
			}
			return &protobufs.ServerToAgent{}
		},
		OnConnectionClose: func(_ servertypes.Connection) {
			if didShutdown.Load() {
				return
			}
			isConnected.Store(false)
			disconnects.Add(1)
		},
	}

	s := server.New(nil)
	handler, connContext, err := s.Attach(server.Settings{
		PayloadSigner: signer,
		Callbacks: servertypes.Callbacks{
			OnConnecting: func(*http.Request) servertypes.ConnectionResponse {
				return servertypes.ConnectionResponse{
					Accept:              true,
					ConnectionCallbacks: callbacks,
				}
			},
		},
	})
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/opamp", handler)
	httpSrv := httptest.NewUnstartedServer(mux)
	httpSrv.Config.ConnContext = connContext
	httpSrv.Start()

	t.Cleanup(func() {
		didShutdown.Store(true)
		assert.NoError(t, s.Stop(context.Background()))
		httpSrv.Close()
	})

	send := func(msg *protobufs.ServerToAgent) {
		if !isConnected.Load() {
			require.Fail(t, "extension is not connected")
		}
		require.NoError(t, agentConn.Load().(servertypes.Connection).Send(context.Background(), msg))
	}

	return &extensionTestServer{
		endpoint:    httpSrv.Listener.Addr().String(),
		disconnects: &disconnects,
		statusChan:  statusChan,
		connected:   connectedChan,
		negotiated:  negotiatedChan,
		send:        send,
	}
}

// startAttestationExtension constructs and starts an opampAgent
// pointing at endpoint. When caCertFile != "", the extension is
// configured to require attestation. Returns the started agent; the
// caller does NOT need to Shutdown — t.Cleanup handles it.
func startAttestationExtension(t *testing.T, endpoint, caCertFile string) *opampAgent {
	t.Helper()

	cfg := createDefaultConfig().(*Config)
	cfg.Server = &OpAMPServer{
		WS: &commonFields{Endpoint: "ws://" + endpoint + "/v1/opamp"},
	}
	if caCertFile != "" {
		cfg.Capabilities.RequiresPayloadTrustVerification = true
		cfg.Signing = Signing{CACertFile: caCertFile}
	}

	set := extensiontest.NewNopSettings(extensiontest.NopType)
	o, err := newOpampAgent(cfg, set)
	require.NoError(t, err)
	require.NoError(t, o.Start(t.Context(), componenttest.NewNopHost()))
	t.Cleanup(func() { _ = o.Shutdown(context.Background()) })
	return o
}

// e2eExtensionTamperingSigner wraps another signer and corrupts the
// signature bytes from the Nth Sign call onward. Slice-copy-then-
// mutate avoids poisoning any pooled buffer the inner signer might
// reuse.
type e2eExtensionTamperingSigner struct {
	inner          signing.Signer
	callN          atomic.Int32
	tamperFromCall int32
}

func (s *e2eExtensionTamperingSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	n := s.callN.Add(1)
	sig, err := s.inner.Sign(ctx, payload)
	if err != nil {
		return nil, err
	}
	if s.tamperFromCall > 0 && n >= s.tamperFromCall && len(sig) > 0 {
		out := make([]byte, len(sig))
		copy(out, sig)
		out[0] ^= 0xff
		return out, nil
	}
	return sig, nil
}

func (s *e2eExtensionTamperingSigner) ChainDER(ctx context.Context) ([][]byte, error) {
	return s.inner.ChainDER(ctx)
}

// TestOpampExtension_PayloadTrustVerification exercises the extension's
// OpAMP Message Attestation wiring (capability bit + signing.ca_cert_file)
// end-to-end against a real OpAMP server. Mirror of the supervisor's
// e2e_attestation_test.go.
func TestOpampExtension_PayloadTrustVerification(t *testing.T) {
	t.Run("Accepts signed handshake and acknowledges remote config", func(t *testing.T) {
		serverSigner, caPath := makeAttestationTestSigner(t)
		srv := newExtensionTestServer(t, serverSigner)

		_ = startAttestationExtension(t, srv.endpoint, caPath)

		select {
		case <-srv.negotiated:
			// First AgentToServer landed → server-side
			// markNegotiated has been called; Send is safe.
		case <-time.After(10 * time.Second):
			t.Fatal("extension did not complete attestation negotiation within 10s")
		}

		// Push a RemoteConfig; the server signs it via PayloadSigner.
		// The extension verifies, processes, and reports back a
		// RemoteConfigStatus. Any status proves the envelope was
		// unwrapped and the inner payload reached the extension.
		hash := []byte("test-config-hash")
		srv.send(&protobufs.ServerToAgent{
			RemoteConfig: &protobufs.AgentRemoteConfig{
				Config: &protobufs.AgentConfigMap{
					ConfigMap: map[string]*protobufs.AgentConfigFile{
						"": {Body: []byte("receivers:\n  nop:\n")},
					},
				},
				ConfigHash: hash,
			},
		})

		select {
		case status := <-srv.statusChan:
			require.NotNil(t, status, "expected RemoteConfigStatus from extension")
		case <-time.After(10 * time.Second):
			t.Fatal("extension did not report any RemoteConfigStatus within 10s")
		}
	})

	t.Run("Drops when server has no signer (missing trust chain)", func(t *testing.T) {
		_, caPath := makeAttestationTestSigner(t)
		// nil signer: server emits plain ServerToAgent bytes; the
		// extension's verifier sees them as a malformed envelope and
		// rejects.
		srv := newExtensionTestServer(t, nil)

		_ = startAttestationExtension(t, srv.endpoint, caPath)

		// At least one connect/disconnect cycle must happen — proves
		// the extension is trying and failing rather than just slow
		// to start.
		require.Eventually(t, func() bool { return srv.disconnects.Load() >= 1 },
			10*time.Second, 200*time.Millisecond,
			"expected at least one reject/reconnect cycle")
	})

	t.Run("Drops on wrong CA", func(t *testing.T) {
		serverSigner, _ := makeAttestationTestSigner(t) // server signs with CA1
		_, otherCAPath := makeAttestationTestSigner(t)  // extension trusts CA2
		srv := newExtensionTestServer(t, serverSigner)

		_ = startAttestationExtension(t, srv.endpoint, otherCAPath)

		require.Eventually(t, func() bool { return srv.disconnects.Load() >= 1 },
			10*time.Second, 200*time.Millisecond,
			"expected at least one reject/reconnect cycle")
	})

	t.Run("Drops on tampered subsequent signature", func(t *testing.T) {
		innerSigner, caPath := makeAttestationTestSigner(t)
		// First Sign (handshake) is intact; every subsequent Sign is
		// corrupted.
		signer := &e2eExtensionTamperingSigner{inner: innerSigner, tamperFromCall: 2}
		srv := newExtensionTestServer(t, signer)

		_ = startAttestationExtension(t, srv.endpoint, caPath)

		// Wait for negotiation to complete — proves the extension
		// accepted the first signed envelope AND it's safe to call
		// Send (markNegotiated has been called server-side).
		select {
		case <-srv.negotiated:
		case <-time.After(10 * time.Second):
			t.Fatal("extension did not complete attestation negotiation within 10s")
		}

		// Pin the tamper boundary: only the handshake Sign has
		// happened so far. If a future server-side keepalive added
		// a Sign call here, tamperFromCall=2 would silently shift
		// meaning. Fail loudly instead.
		require.LessOrEqual(t, signer.callN.Load(), int32(2),
			"tamper-from-call=2 assumes ≤2 Sign calls before the push")

		// Push a server-initiated message; its signature will be
		// corrupted. The extension's WS receive loop will reject and
		// terminate.
		disconnectsBefore := srv.disconnects.Load()
		srv.send(&protobufs.ServerToAgent{
			CustomMessage: &protobufs.CustomMessage{Capability: "test/tamper"},
		})

		require.Eventually(t, func() bool {
			return srv.disconnects.Load() > disconnectsBefore
		}, 10*time.Second, 100*time.Millisecond,
			"extension should disconnect after the tampered envelope")
	})
}
