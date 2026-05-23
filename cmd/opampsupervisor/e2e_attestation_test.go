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

// newSigningOpAMPServer is the attestation-aware variant of
// newOpAMPServer: it injects the supplied signing.Signer into
// server.Settings so outbound ServerToAgent messages are wrapped in
// SignedServerToAgent envelopes once the supervisor declares the
// RequiresPayloadTrustVerification capability bit.
func newSigningOpAMPServer(t *testing.T, signer signing.Signer, callbacks types.ConnectionCallbacks) *testingOpAMPServer {
	t.Helper()

	var agentConn atomic.Value
	var isAgentConnected atomic.Bool
	var didShutdown atomic.Bool
	connectedChan := make(chan bool, 8) // small buffer; reject scenarios may emit several connect/disconnect events
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
		// Best-effort signal; drop if no reader.
		select {
		case connectedChan <- true:
		default:
		}
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
			assert.NoError(t, s.Stop(context.Background()))
			httpSrv.Close()
		}
	}
	send := func(msg *protobufs.ServerToAgent) {
		if !isAgentConnected.Load() {
			require.Fail(t, "Agent connection has not been established")
		}
		require.NoError(t, agentConn.Load().(types.Connection).Send(context.Background(), msg))
	}
	t.Cleanup(shutdown)

	httpSrv.Start()
	return &testingOpAMPServer{
		addr:                httpSrv.Listener.Addr().String(),
		supervisorConnected: connectedChan,
		sendToSupervisor:    send,
		start:               httpSrv.Start,
		shutdown:            shutdown,
	}
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

// drainConnectionEvents pulls all pending events from the channel so
// reject-scenario "wait for disconnect" loops don't pick up a stale
// "connected" event left over from the initial handshake.
func drainConnectionEvents(ch chan bool) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// TestSupervisorPayloadTrustVerification exercises the supervisor's
// OpAMP Message Attestation wiring (capability bit + signing.ca_cert_file)
// end-to-end against a real OpAMP server that signs (or fails to sign)
// outbound messages.
func TestSupervisorPayloadTrustVerification(t *testing.T) {
	t.Run("Accepts signed handshake and applies remote config", func(t *testing.T) {
		serverSigner, caPath := makeTestSigner(t)

		var agentConfig atomic.Value
		srv := newSigningOpAMPServer(t, serverSigner, types.ConnectionCallbacks{
			OnMessage: func(_ context.Context, _ types.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
				if message.EffectiveConfig != nil {
					if cfgMap := message.EffectiveConfig.ConfigMap.ConfigMap[""]; cfgMap != nil {
						agentConfig.Store(string(cfgMap.Body))
					}
				}
				return &protobufs.ServerToAgent{}
			},
		})

		s, _ := newSupervisor(t, "payload_attestation", map[string]string{
			"url":          srv.addr,
			"storage_dir":  t.TempDir(),
			"ca_cert_file": caPath,
		})
		require.NoError(t, s.Start(t.Context()))
		t.Cleanup(s.Shutdown)

		waitForSupervisorConnection(srv.supervisorConnected, true)

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
		// No PayloadSigner on the server — it emits plain
		// ServerToAgent bytes, which the supervisor's OpAMP client
		// parses as a SignedServerToAgent envelope missing its trust
		// chain and rejects.
		srv := newOpAMPServer(t, defaultConnectingHandler, types.ConnectionCallbacks{
			OnMessage: func(_ context.Context, _ types.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
				if message.EffectiveConfig != nil {
					if cfgMap := message.EffectiveConfig.ConfigMap.ConfigMap[""]; cfgMap != nil {
						agentConfig.Store(string(cfgMap.Body))
					}
				}
				return &protobufs.ServerToAgent{}
			},
		})

		s, _ := newSupervisor(t, "payload_attestation", map[string]string{
			"url":          srv.addr,
			"storage_dir":  t.TempDir(),
			"ca_cert_file": caPath,
		})
		require.NoError(t, s.Start(t.Context()))
		t.Cleanup(s.Shutdown)

		// The supervisor must NEVER apply a message that failed
		// attestation. We use Never so a flaky/transient connection
		// state can't slip a verified message through.
		require.Never(t, func() bool {
			return agentConfig.Load() != nil
		}, 4*time.Second, 200*time.Millisecond,
			"supervisor must not deliver any message that failed attestation")
	})

	t.Run("Drops on wrong CA", func(t *testing.T) {
		serverSigner, _ := makeTestSigner(t) // server signs with CA1
		_, otherCAPath := makeTestSigner(t)  // supervisor trusts an independent CA2

		var agentConfig atomic.Value
		srv := newSigningOpAMPServer(t, serverSigner, types.ConnectionCallbacks{
			OnMessage: func(_ context.Context, _ types.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
				if message.EffectiveConfig != nil {
					if cfgMap := message.EffectiveConfig.ConfigMap.ConfigMap[""]; cfgMap != nil {
						agentConfig.Store(string(cfgMap.Body))
					}
				}
				return &protobufs.ServerToAgent{}
			},
		})

		s, _ := newSupervisor(t, "payload_attestation", map[string]string{
			"url":          srv.addr,
			"storage_dir":  t.TempDir(),
			"ca_cert_file": otherCAPath,
		})
		require.NoError(t, s.Start(t.Context()))
		t.Cleanup(s.Shutdown)

		require.Never(t, func() bool {
			return agentConfig.Load() != nil
		}, 4*time.Second, 200*time.Millisecond,
			"supervisor must reject messages signed by an untrusted CA")
	})

	t.Run("Drops on tampered subsequent signature", func(t *testing.T) {
		innerSigner, caPath := makeTestSigner(t)
		// First Sign (the connection-response handshake) is intact;
		// every subsequent Sign returns a corrupted signature.
		signer := &e2eTamperingSigner{inner: innerSigner, tamperFromCall: 2}

		var msgCount atomic.Int32
		srv := newSigningOpAMPServer(t, signer, types.ConnectionCallbacks{
			OnMessage: func(_ context.Context, _ types.Connection, _ *protobufs.AgentToServer) *protobufs.ServerToAgent {
				msgCount.Add(1)
				return &protobufs.ServerToAgent{}
			},
		})

		s, _ := newSupervisor(t, "payload_attestation", map[string]string{
			"url":          srv.addr,
			"storage_dir":  t.TempDir(),
			"ca_cert_file": caPath,
		})
		require.NoError(t, s.Start(t.Context()))
		t.Cleanup(s.Shutdown)

		// Wait for the first OnMessage (handshake) to land on the
		// server — proves the supervisor accepted the first signed
		// envelope.
		require.Eventually(t, func() bool { return msgCount.Load() >= 1 },
			10*time.Second, 100*time.Millisecond,
			"supervisor should accept the first signed envelope")

		// Drain "connected" events from the handshake so the
		// disconnect we wait for below isn't masked.
		drainConnectionEvents(srv.supervisorConnected)

		// Server-initiated push with a corrupted signature; the
		// supervisor's WS receive loop will reject and terminate.
		srv.sendToSupervisor(&protobufs.ServerToAgent{
			CustomMessage: &protobufs.CustomMessage{Capability: "test/tamper"},
		})

		select {
		case state := <-srv.supervisorConnected:
			require.False(t, state, "expected a disconnect after tampered signature")
		case <-time.After(10 * time.Second):
			t.Fatal("supervisor did not disconnect on tampered signature")
		}
	})
}
