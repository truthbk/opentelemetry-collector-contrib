// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server"
	"github.com/open-telemetry/opamp-go/server/types"
	"github.com/open-telemetry/opamp-go/signing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestSigner generates an ephemeral ECDSA P-256 CA + leaf pair and
// returns a LocalSigner the OpAMP server uses to sign outbound messages
// plus the on-disk PEM path the supervisor's signing.ca_cert_file
// points at.
func makeTestSigner(t *testing.T) (*signing.LocalSigner, string) {
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

// captureEffectiveConfig returns an OnMessage callback that records
// the most recent EffectiveConfig payload into store. Used by the
// reject + happy-path sub-tests below to drive an "agent applied a
// config" predicate.
func captureEffectiveConfig(store *atomic.Value) func(context.Context, types.Connection, *protobufs.AgentToServer) *protobufs.ServerToAgent {
	return func(_ context.Context, _ types.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
		if message.EffectiveConfig != nil {
			if cfgMap := message.EffectiveConfig.ConfigMap.ConfigMap[""]; cfgMap != nil {
				store.Store(string(cfgMap.Body))
			}
		}
		return &protobufs.ServerToAgent{}
	}
}

// newSigningOpAMPServer is the attestation-aware variant of
// newOpAMPServer: it injects the supplied signing.Signer into
// server.Settings so outbound ServerToAgent messages are wrapped in
// SignedServerToAgent envelopes once the supervisor declares the
// RequiresPayloadTrustVerification capability bit.
//
// Returns the server plus a `negotiated` channel that closes after
// the first OnMessage lands on the server — equivalent to saying
// "server-side markNegotiated has been called". Callers that want
// to push server-initiated messages via sendToSupervisor MUST wait
// on this channel first, otherwise Send may trip opamp-go's
// ErrSendBeforeNegotiated guard.
//
// Divergence from newOpAMPServer: connect/disconnect events go onto a
// buffered channel with non-blocking sends. Reject scenarios produce
// repeated reconnect cycles; an unbuffered channel would deadlock the
// server goroutine once a test stopped consuming. Reject tests should
// therefore observe disconnect cycles via a user-supplied
// OnConnectionClose callback (which the wrapper invokes
// unconditionally) rather than by draining the channel directly.
func newSigningOpAMPServer(t *testing.T, signer signing.Signer, callbacks types.ConnectionCallbacks) (*testingOpAMPServer, <-chan struct{}) {
	t.Helper()

	var agentConn atomic.Value
	var isAgentConnected atomic.Bool
	var didShutdown atomic.Bool
	var negotiatedOnce atomic.Bool
	connectedChan := make(chan bool, 64) // generous buffer; sends are best-effort (see helper doc above)
	negotiatedChan := make(chan struct{})
	s := server.New(testLogger{t: t})

	onConnectedFunc := callbacks.OnConnected
	callbacks.OnConnected = func(ctx context.Context, conn types.Connection) {
		if didShutdown.Load() {
			return
		}
		if onConnectedFunc != nil {
			onConnectedFunc(ctx, conn)
		}
		agentConn.Store(conn)
		isAgentConnected.Store(true)
		select {
		case connectedChan <- true:
		default:
		}
	}
	onMessageFunc := callbacks.OnMessage
	callbacks.OnMessage = func(ctx context.Context, conn types.Connection, msg *protobufs.AgentToServer) *protobufs.ServerToAgent {
		// First OnMessage implies server-side markNegotiated has
		// been called; Send is now safe.
		if negotiatedOnce.CompareAndSwap(false, true) {
			close(negotiatedChan)
		}
		if onMessageFunc != nil {
			return onMessageFunc(ctx, conn, msg)
		}
		return &protobufs.ServerToAgent{}
	}
	onConnectionCloseFunc := callbacks.OnConnectionClose
	callbacks.OnConnectionClose = func(conn types.Connection) {
		if didShutdown.Load() {
			return
		}
		isAgentConnected.Store(false)
		select {
		case connectedChan <- false:
		default:
		}
		if onConnectionCloseFunc != nil {
			onConnectionCloseFunc(conn)
		}
	}

	handler, connContext, err := s.Attach(server.Settings{
		PayloadSigner: signer,
		Callbacks: types.Callbacks{
			OnConnecting: defaultConnectingHandler(callbacks),
		},
	})
	require.NoError(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/opamp", handler)
	httpSrv := httptest.NewUnstartedServer(mux)
	httpSrv.Config.ConnContext = connContext

	shutdown := func() {
		if didShutdown.CompareAndSwap(false, true) {
			t.Log("Shutting down attestation OpAMP server")
			assert.NoError(t, s.Stop(t.Context()))
			httpSrv.Close()
		}
	}
	send := func(msg *protobufs.ServerToAgent) {
		if !isAgentConnected.Load() {
			require.Fail(t, "Agent connection has not been established")
		}
		require.NoError(t, agentConn.Load().(types.Connection).Send(t.Context(), msg))
	}
	t.Cleanup(shutdown)

	httpSrv.Start()
	return &testingOpAMPServer{
		addr:                httpSrv.Listener.Addr().String(),
		supervisorConnected: connectedChan,
		sendToSupervisor:    send,
		start:               httpSrv.Start,
		shutdown:            shutdown,
	}, negotiatedChan
}

// e2eTamperingSigner wraps another signer and corrupts the signature
// bytes starting from the Nth Sign call (1-indexed). Used to drive
// the "tampered subsequent signature" reject scenario end-to-end. The
// inner signature is copied before mutation so we don't poison a
// pooled buffer the inner signer might reuse.
type e2eTamperingSigner struct {
	inner          signing.Signer
	callN          atomic.Int32
	tamperFromCall int32
}

func (s *e2eTamperingSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
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

func (s *e2eTamperingSigner) ChainDER(ctx context.Context) ([][]byte, error) {
	return s.inner.ChainDER(ctx)
}

// TestSupervisorPayloadTrustVerification exercises the supervisor's
// OpAMP Message Attestation wiring (capability bit + signing.ca_cert_file)
// end-to-end against a real OpAMP server that signs (or fails to sign)
// outbound messages.
func TestSupervisorPayloadTrustVerification(t *testing.T) {
	t.Run("Accepts signed handshake and applies remote config", func(t *testing.T) {
		serverSigner, caPath := makeTestSigner(t)

		var agentConfig atomic.Value
		srv, negotiated := newSigningOpAMPServer(t, serverSigner, types.ConnectionCallbacks{
			OnMessage: captureEffectiveConfig(&agentConfig),
		})

		s, _ := newSupervisor(t, "payload_attestation", map[string]string{
			"url":          srv.addr,
			"storage_dir":  t.TempDir(),
			"ca_cert_file": caPath,
		})
		require.NoError(t, s.Start(t.Context()))
		t.Cleanup(s.Shutdown)

		// Wait for the supervisor's first AgentToServer to land on
		// the server — that's when server-side markNegotiated runs,
		// after which sendToSupervisor is safe.
		select {
		case <-negotiated:
		case <-time.After(10 * time.Second):
			t.Fatal("supervisor did not complete attestation negotiation within 10s")
		}

		cfg, hash, _, _ := createSimplePipelineCollectorConf(t)
		srv.sendToSupervisor(&protobufs.ServerToAgent{
			RemoteConfig: &protobufs.AgentRemoteConfig{
				Config: &protobufs.AgentConfigMap{
					ConfigMap: map[string]*protobufs.AgentConfigFile{
						"": {Body: cfg.Bytes()},
					},
				},
				ConfigHash: hash,
			},
		})

		require.Eventually(t, func() bool {
			v, ok := agentConfig.Load().(string)
			return ok && strings.Contains(v, "file_log")
		}, 10*time.Second, 500*time.Millisecond,
			"supervisor should have applied the signed remote config")
	})

	t.Run("Drops when server has no signer (missing trust chain)", func(t *testing.T) {
		_, caPath := makeTestSigner(t)

		var agentConfig atomic.Value
		var disconnects atomic.Int32
		// No PayloadSigner on the server — it emits plain
		// ServerToAgent bytes, which the supervisor's OpAMP client
		// parses as a SignedServerToAgent envelope missing its trust
		// chain and rejects. The supervisor reconnect-loops; each
		// failed handshake increments `disconnects`.
		srv := newOpAMPServer(t, defaultConnectingHandler, types.ConnectionCallbacks{
			OnMessage: captureEffectiveConfig(&agentConfig),
			OnConnectionClose: func(_ types.Connection) {
				disconnects.Add(1)
			},
		})

		s, _ := newSupervisor(t, "payload_attestation", map[string]string{
			"url":          srv.addr,
			"storage_dir":  t.TempDir(),
			"ca_cert_file": caPath,
		})
		require.NoError(t, s.Start(t.Context()))
		t.Cleanup(s.Shutdown)

		// Positive signal: the supervisor IS trying — at least one
		// reconnect cycle completed. Without this, a Never assertion
		// could pass for the wrong reason (supervisor never started).
		require.Eventually(t, func() bool { return disconnects.Load() >= 1 },
			10*time.Second, 200*time.Millisecond,
			"expected at least one reject/reconnect cycle")

		// Push a RemoteConfig so agentConfig has something to be
		// "never populated by" — if attestation were broken the
		// supervisor would apply this and report it back via
		// EffectiveConfig.
		cfg, hash, _, _ := createSimplePipelineCollectorConf(t)
		srv.sendToSupervisor(&protobufs.ServerToAgent{
			RemoteConfig: &protobufs.AgentRemoteConfig{
				Config: &protobufs.AgentConfigMap{
					ConfigMap: map[string]*protobufs.AgentConfigFile{
						"": {Body: cfg.Bytes()},
					},
				},
				ConfigHash: hash,
			},
		})

		// Supervisor must NEVER apply the unverified config.
		require.Never(t, func() bool {
			v, ok := agentConfig.Load().(string)
			return ok && strings.Contains(v, "file_log")
		}, 4*time.Second, 200*time.Millisecond,
			"supervisor must not apply a config that failed attestation")
	})

	t.Run("Drops on wrong CA", func(t *testing.T) {
		serverSigner, _ := makeTestSigner(t) // server signs with CA1
		_, otherCAPath := makeTestSigner(t)  // supervisor trusts an independent CA2

		var agentConfig atomic.Value
		var disconnects atomic.Int32
		// negotiated will never close in this scenario (no message
		// ever passes verification) — discard it.
		srv, _ := newSigningOpAMPServer(t, serverSigner, types.ConnectionCallbacks{
			OnMessage: captureEffectiveConfig(&agentConfig),
			OnConnectionClose: func(_ types.Connection) {
				disconnects.Add(1)
			},
		})

		s, _ := newSupervisor(t, "payload_attestation", map[string]string{
			"url":          srv.addr,
			"storage_dir":  t.TempDir(),
			"ca_cert_file": otherCAPath,
		})
		require.NoError(t, s.Start(t.Context()))
		t.Cleanup(s.Shutdown)

		require.Eventually(t, func() bool { return disconnects.Load() >= 1 },
			10*time.Second, 200*time.Millisecond,
			"expected at least one reject/reconnect cycle")

		cfg, hash, _, _ := createSimplePipelineCollectorConf(t)
		srv.sendToSupervisor(&protobufs.ServerToAgent{
			RemoteConfig: &protobufs.AgentRemoteConfig{
				Config: &protobufs.AgentConfigMap{
					ConfigMap: map[string]*protobufs.AgentConfigFile{
						"": {Body: cfg.Bytes()},
					},
				},
				ConfigHash: hash,
			},
		})

		require.Never(t, func() bool {
			v, ok := agentConfig.Load().(string)
			return ok && strings.Contains(v, "file_log")
		}, 4*time.Second, 200*time.Millisecond,
			"supervisor must not apply a config signed by an untrusted CA")
	})

	t.Run("Drops on tampered subsequent signature", func(t *testing.T) {
		innerSigner, caPath := makeTestSigner(t)
		// First Sign (the connection-response handshake) is intact;
		// every subsequent Sign returns a corrupted signature.
		signer := &e2eTamperingSigner{inner: innerSigner, tamperFromCall: 2}

		var disconnectsBefore atomic.Int32
		var disconnects atomic.Int32
		srv, negotiated := newSigningOpAMPServer(t, signer, types.ConnectionCallbacks{
			OnConnectionClose: func(_ types.Connection) {
				disconnects.Add(1)
			},
		})

		s, _ := newSupervisor(t, "payload_attestation", map[string]string{
			"url":          srv.addr,
			"storage_dir":  t.TempDir(),
			"ca_cert_file": caPath,
		})
		require.NoError(t, s.Start(t.Context()))
		t.Cleanup(s.Shutdown)

		// Wait for the first OnMessage to land — proves the supervisor
		// accepted the first signed envelope (call #1) AND that
		// markNegotiated has been called server-side so sendToSupervisor
		// is safe.
		select {
		case <-negotiated:
		case <-time.After(10 * time.Second):
			t.Fatal("supervisor did not complete attestation negotiation within 10s")
		}

		// Pin the tamper boundary: only one Sign call has happened so
		// far (the handshake response). If a future server-side
		// keepalive added an extra Sign here, tamperFromCall: 2 would
		// silently shift meaning and the test would assert against the
		// wrong message. Fail loudly instead.
		require.Equal(t, int32(1), signer.callN.Load(),
			"tamper-from-call=2 assumes exactly one Sign before the explicit push")

		// Snapshot the disconnect count so we observe a NEW disconnect
		// (not one left over from any pre-handshake retry).
		disconnectsBefore.Store(disconnects.Load())

		// Server-initiated push with a corrupted signature; the
		// supervisor's WS receive loop will reject and terminate.
		srv.sendToSupervisor(&protobufs.ServerToAgent{
			CustomMessage: &protobufs.CustomMessage{Capability: "test/tamper"},
		})

		require.Eventually(t, func() bool {
			return disconnects.Load() > disconnectsBefore.Load()
		}, 10*time.Second, 100*time.Millisecond,
			"supervisor should disconnect after the tampered envelope")
	})

	t.Run("Accepts signed handshake over HTTP transport", func(t *testing.T) {
		// Mirror of the WS happy-path test but exercises the HTTP
		// polling transport. The supervisor's HTTP receive path has
		// its own attestation-reset logic (httpsender.go:Reset on
		// attestation failure) that's not exercised by the WS
		// tests — this is the wire-up smoke for that path.
		serverSigner, caPath := makeTestSigner(t)

		var agentConfig atomic.Value
		srv, negotiated := newSigningOpAMPServer(t, serverSigner, types.ConnectionCallbacks{
			OnMessage: captureEffectiveConfig(&agentConfig),
		})

		s, _ := newSupervisor(t, "payload_attestation_http", map[string]string{
			"url":          srv.addr,
			"storage_dir":  t.TempDir(),
			"ca_cert_file": caPath,
		})
		require.NoError(t, s.Start(t.Context()))
		t.Cleanup(s.Shutdown)

		select {
		case <-negotiated:
		case <-time.After(15 * time.Second):
			// HTTP polling has a 30s default interval, but the
			// supervisor's first poll is essentially immediate after
			// Start. Give it a bit more headroom than the WS case.
			t.Fatal("supervisor did not complete attestation negotiation over HTTP within 15s")
		}

		cfg, hash, _, _ := createSimplePipelineCollectorConf(t)
		srv.sendToSupervisor(&protobufs.ServerToAgent{
			RemoteConfig: &protobufs.AgentRemoteConfig{
				Config: &protobufs.AgentConfigMap{
					ConfigMap: map[string]*protobufs.AgentConfigFile{
						"": {Body: cfg.Bytes()},
					},
				},
				ConfigHash: hash,
			},
		})

		require.Eventually(t, func() bool {
			v, ok := agentConfig.Load().(string)
			return ok && strings.Contains(v, "file_log")
		}, 30*time.Second, 1*time.Second,
			"supervisor should apply the signed remote config over HTTP within 30s")
	})
}
