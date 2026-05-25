// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// smoke-test-opamp-attestation-server is a minimal OpAMP server used
// by scripts/smoke-test-opamp-attestation.sh to validate the OpAMP
// Message Attestation (X.509 payload trust verification) flow
// end-to-end against a real opampsupervisor process.
//
// The server:
//
//  1. Generates an ECDSA P-256 CA + leaf certificate; writes the CA
//     PEM bundle to --ca-out so the supervisor's signing.ca_cert_file
//     can point at it.
//  2. Starts a WebSocket OpAMP server on --port with a PayloadSigner
//     configured. Outbound messages to a supervisor that declares
//     RequiresPayloadTrustVerification are wrapped in
//     SignedServerToAgent envelopes.
//  3. Waits for a supervisor to connect.
//  4. Sends a RemoteConfig (auto-signed by the server's PayloadSigner).
//  5. Waits for a follow-up AgentToServer carrying a non-nil
//     RemoteConfigStatus — any status (APPLIED, APPLYING, FAILED)
//     proves the supervisor accepted the SignedServerToAgent envelope,
//     unwrapped it, and acted on the inner payload.
//  6. Emits "SMOKE_TEST_PASS" or "SMOKE_TEST_FAIL" to stdout and exits.
//
// Usage:
//
//	smoke-test-opamp-attestation-server --port 14320 --ca-out /tmp/ca.pem
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server"
	serverTypes "github.com/open-telemetry/opamp-go/server/types"
	"github.com/open-telemetry/opamp-go/signing"
)

var (
	port         = flag.Int("port", 14320, "port to listen on")
	caOut        = flag.String("ca-out", "/tmp/ca.pem", "path to write the generated CA PEM")
	connectWait  = flag.Duration("connect-timeout", 30*time.Second, "how long to wait for the supervisor to connect")
	responseWait = flag.Duration("response-timeout", 30*time.Second, "how long to wait for the supervisor's RemoteConfigStatus after the signed push")
)

// collectorConfig is a minimal collector config body the server
// pushes as remote config. Validity isn't checked here; the smoke
// test only cares that the supervisor accepts the SignedServerToAgent
// envelope and reports a RemoteConfigStatus back.
const collectorConfig = `
receivers:
  nop:
exporters:
  nop:
service:
  pipelines:
    traces:
      receivers: [nop]
      exporters: [nop]
`

func fail(format string, args ...any) {
	log.Printf(format, args...)
	fmt.Println("SMOKE_TEST_FAIL")
	os.Exit(1)
}

func pass(format string, args ...any) {
	log.Printf(format, args...)
	fmt.Println("SMOKE_TEST_PASS")
	os.Exit(0)
}

func main() {
	flag.Parse()

	// Step 1: Generate an ephemeral ECDSA P-256 CA + leaf; build a
	// LocalSigner that signs with the leaf and writes the CA PEM out
	// so the supervisor's signing.ca_cert_file config can point at it.
	ca, caKey, err := signing.GenerateCA(signing.AlgorithmECDSAP256SHA256, signing.CertOptions{})
	if err != nil {
		fail("GenerateCA: %v", err)
	}
	leaf, leafKey, err := signing.GenerateLeaf(signing.AlgorithmECDSAP256SHA256, ca, caKey, signing.CertOptions{})
	if err != nil {
		fail("GenerateLeaf: %v", err)
	}
	signer, err := signing.NewLocalSigner(leafKey, []*x509.Certificate{leaf})
	if err != nil {
		fail("NewLocalSigner: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err := os.WriteFile(*caOut, caPEM, 0o600); err != nil {
		fail("write ca.pem at %s: %v", *caOut, err)
	}
	log.Printf("CA cert written to %s", *caOut)

	// Step 2: Start the OpAMP server with PayloadSigner configured.
	var (
		mu              sync.Mutex
		agentConn       serverTypes.Connection
		agentConnected  = make(chan struct{}, 1)
		statusUpdate    = make(chan *protobufs.RemoteConfigStatus, 8)
		expectedConfig  *protobufs.AgentRemoteConfig
		expectedHashHex string
	)

	connCallbacks := serverTypes.ConnectionCallbacks{
		OnConnected: func(_ context.Context, conn serverTypes.Connection) {
			mu.Lock()
			if agentConn == nil {
				agentConn = conn
				select {
				case agentConnected <- struct{}{}:
				default:
				}
			}
			mu.Unlock()
			log.Printf("supervisor connected")
		},
		OnMessage: func(_ context.Context, _ serverTypes.Connection, msg *protobufs.AgentToServer) *protobufs.ServerToAgent {
			if msg.RemoteConfigStatus != nil {
				log.Printf("RemoteConfigStatus: status=%v hash=%x err=%q",
					msg.RemoteConfigStatus.GetStatus(),
					msg.RemoteConfigStatus.GetLastRemoteConfigHash(),
					msg.RemoteConfigStatus.GetErrorMessage(),
				)
				select {
				case statusUpdate <- msg.RemoteConfigStatus:
				default:
				}
			}
			return &protobufs.ServerToAgent{}
		},
	}

	opampSrv := server.New(nil)
	settings := server.StartSettings{
		Settings: server.Settings{
			PayloadSigner: signer,
			Callbacks: serverTypes.Callbacks{
				OnConnecting: func(_ *http.Request) serverTypes.ConnectionResponse {
					return serverTypes.ConnectionResponse{
						Accept:              true,
						ConnectionCallbacks: connCallbacks,
					}
				},
			},
		},
		ListenEndpoint: fmt.Sprintf("127.0.0.1:%d", *port),
		ListenPath:     "/v1/opamp",
	}
	if err := opampSrv.Start(settings); err != nil {
		fail("opampSrv.Start: %v", err)
	}
	defer func() { _ = opampSrv.Stop(context.Background()) }()
	log.Printf("OpAMP server listening on 127.0.0.1:%d", *port)

	// Step 3: Wait for the supervisor to connect.
	select {
	case <-agentConnected:
	case <-time.After(*connectWait):
		fail("timed out after %s waiting for supervisor to connect", *connectWait)
	}

	// Step 4: Send a signed RemoteConfig.
	hash := sha256.Sum256([]byte(collectorConfig))
	expectedHashHex = fmt.Sprintf("%x", hash[:])
	expectedConfig = &protobufs.AgentRemoteConfig{
		Config: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"": {Body: []byte(collectorConfig)},
			},
		},
		ConfigHash: hash[:],
	}

	mu.Lock()
	conn := agentConn
	mu.Unlock()
	if conn == nil {
		fail("internal: agentConn nil after agentConnected fired")
	}

	log.Printf("sending signed RemoteConfig (hash=%s)", expectedHashHex)
	if err := conn.Send(context.Background(), &protobufs.ServerToAgent{
		RemoteConfig: expectedConfig,
	}); err != nil {
		fail("send signed RemoteConfig: %v", err)
	}

	// Step 5: Wait for any RemoteConfigStatus that references the hash
	// we just sent. Any status (APPLIED, APPLYING, FAILED) is a
	// positive signal that the supervisor unwrapped and verified the
	// SignedServerToAgent envelope and acted on the inner payload.
	// We deliberately accept FAILED — without a real collector behind
	// the supervisor the apply step may fail, but the attestation
	// itself succeeded if we got this far.
	deadline := time.Now().Add(*responseWait)
	for {
		select {
		case s := <-statusUpdate:
			if fmt.Sprintf("%x", s.GetLastRemoteConfigHash()) == expectedHashHex {
				pass("supervisor reported RemoteConfigStatus=%v for the signed config (attestation verified end-to-end)",
					s.GetStatus())
			}
			// Other status hashes (e.g., for an initial empty config)
			// are ignored; keep waiting.
		case <-time.After(time.Until(deadline)):
			fail("timed out after %s waiting for the supervisor to acknowledge the signed config", *responseWait)
		}
	}
}
