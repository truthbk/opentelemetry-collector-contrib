// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// smoke-test-opamp-x509-server is a minimal OpAMP server used by the
// smoke-test-opamp-x509.sh script to validate X.509 remote config signing
// end-to-end.
//
// The server:
//  1. Generates an ECDSA P-256 CA and leaf certificate; writes ca.pem to --ca-out.
//  2. Starts a WebSocket OpAMP server on --port.
//  3. Waits for an agent to connect, then sends a SIGNED remote config.
//  4. Waits for RemoteConfigStatus = APPLIED.
//  5. Sends an UNSIGNED remote config.
//  6. Waits for RemoteConfigStatus = FAILED.
//  7. Emits "SMOKE_TEST_PASS" or "SMOKE_TEST_FAIL" and exits.
//
// Usage:
//
//	smoke-test-opamp-x509-server --port 14320 --ca-out /tmp/ca.pem
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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
	port  = flag.Int("port", 14320, "port to listen on")
	caOut = flag.String("ca-out", "/tmp/ca.pem", "path to write the generated CA PEM")
)

// collectorConfig is a minimal collector config body used in tests.
const collectorConfig = `
receivers:
  noop:
exporters:
  noop:
service:
  pipelines:
    traces:
      receivers: [noop]
      exporters: [noop]
`

func main() {
	flag.Parse()

	// Step 1: Generate CA and leaf, write CA PEM.
	caKey, caCert, caPEM, err := signing.GenerateECDSACA()
	if err != nil {
		log.Fatalf("GenerateECDSACA: %v", err)
	}
	if err := os.WriteFile(*caOut, caPEM, 0o600); err != nil {
		log.Fatalf("write ca.pem: %v", err)
	}
	log.Printf("CA cert written to %s", *caOut)

	leafCert, leafChainPEM, err := signing.GenerateECDSALeafCert(caCert, caKey)
	if err != nil {
		log.Fatalf("GenerateECDSALeafCert: %v", err)
	}
	configSigner, err := signing.NewConfigSigner(leafCert, leafChainPEM)
	if err != nil {
		log.Fatalf("NewConfigSigner: %v", err)
	}

	// Step 2: Start OpAMP server.
	var (
		mu           sync.Mutex
		connections  []serverTypes.Connection
		lastStatus   *protobufs.RemoteConfigStatus
		statusUpdate = make(chan *protobufs.RemoteConfigStatus, 10)
	)

	connCallbacks := serverTypes.ConnectionCallbacks{
		OnConnected: func(_ context.Context, conn serverTypes.Connection) {
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			log.Printf("Agent connected")
		},
		OnMessage: func(_ context.Context, _ serverTypes.Connection, msg *protobufs.AgentToServer) *protobufs.ServerToAgent {
			if msg.RemoteConfigStatus != nil {
				mu.Lock()
				lastStatus = msg.RemoteConfigStatus
				mu.Unlock()
				statusUpdate <- msg.RemoteConfigStatus
				log.Printf("RemoteConfigStatus: %v (hash=%x err=%q)",
					msg.RemoteConfigStatus.GetStatus(),
					msg.RemoteConfigStatus.GetLastRemoteConfigHash(),
					msg.RemoteConfigStatus.GetErrorMessage(),
				)
			}
			return nil
		},
	}

	opampSrv := server.New(nil)
	settings := server.StartSettings{
		Settings: server.Settings{
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
	}
	if err := opampSrv.Start(settings); err != nil {
		log.Fatalf("server.Start: %v", err)
	}
	defer func() { _ = opampSrv.Stop(context.Background()) }()
	log.Printf("OpAMP server listening on :%d", *port)

	// Step 3: Wait for an agent to connect (timeout 30s).
	log.Println("Waiting for agent to connect...")
	deadline := time.Now().Add(30 * time.Second)
	for {
		mu.Lock()
		n := len(connections)
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			log.Println("SMOKE_TEST_FAIL: timeout waiting for agent connection")
			os.Exit(1)
		}
		time.Sleep(200 * time.Millisecond)
	}

	sendRemoteConfig := func(conn serverTypes.Connection, rc *protobufs.AgentRemoteConfig) {
		msg := &protobufs.ServerToAgent{
			RemoteConfig: rc,
		}
		if err := conn.Send(context.Background(), msg); err != nil {
			log.Printf("Send error: %v", err)
		}
	}

	waitForStatus := func(want protobufs.RemoteConfigStatuses, timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for {
			select {
			case s := <-statusUpdate:
				if s.GetStatus() == want {
					return true
				}
			case <-time.After(time.Until(deadline)):
				return false
			}
		}
	}

	buildConfig := func(body string) *protobufs.AgentRemoteConfig {
		h := sha256.Sum256([]byte(body))
		return &protobufs.AgentRemoteConfig{
			Config: &protobufs.AgentConfigMap{
				ConfigMap: map[string]*protobufs.AgentConfigFile{
					"": {Body: []byte(body)},
				},
			},
			ConfigHash: h[:],
		}
	}

	mu.Lock()
	conn := connections[0]
	mu.Unlock()

	// Step 4: Send signed config, expect APPLIED.
	log.Println("Sending SIGNED remote config...")
	signedCfg := buildConfig(collectorConfig)
	if err := configSigner.SignConfig(signedCfg); err != nil {
		log.Fatalf("SignConfig: %v", err)
	}
	sendRemoteConfig(conn, signedCfg)

	if !waitForStatus(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED, 20*time.Second) {
		mu.Lock()
		s := lastStatus
		mu.Unlock()
		statusJSON, _ := json.Marshal(s)
		log.Printf("SMOKE_TEST_FAIL: signed config not APPLIED within 20s. Last status: %s", statusJSON)
		os.Exit(1)
	}
	log.Println("  -> APPLIED ✓")

	// Step 5: Send unsigned config, expect FAILED.
	log.Println("Sending UNSIGNED remote config (expect FAILED)...")
	differentBody := collectorConfig + "# unsigned\n"
	unsignedCfg := buildConfig(differentBody)
	// Intentionally NOT signing.
	sendRemoteConfig(conn, unsignedCfg)

	if !waitForStatus(protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED, 20*time.Second) {
		mu.Lock()
		s := lastStatus
		mu.Unlock()
		statusJSON, _ := json.Marshal(s)
		log.Printf("SMOKE_TEST_FAIL: unsigned config not FAILED within 20s. Last status: %s", statusJSON)
		os.Exit(1)
	}
	log.Println("  -> FAILED ✓")

	log.Println("SMOKE_TEST_PASS")

	// Serve an HTTP health endpoint so the shell script can optionally poll.
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
}
