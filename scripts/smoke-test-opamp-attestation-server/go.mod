module github.com/open-telemetry/opentelemetry-collector-contrib/scripts/smoke-test-opamp-attestation-server

go 1.25.0

require github.com/open-telemetry/opamp-go v0.23.0

require (
	github.com/gorilla/websocket v1.5.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/open-telemetry/opamp-go => ../../../opamp-go
