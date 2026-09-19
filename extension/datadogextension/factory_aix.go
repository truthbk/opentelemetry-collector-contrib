// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build aix

package datadogextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/datadogextension"
import "go.opentelemetry.io/collector/extension"

// factory exists only so Option has the same shape here as on supported platforms.
type factory struct{}

// Option configures the Datadog extension factory. WithConfigOptions is absent here:
// its parameter type lives in pkg/datadog/agentcomponents, which does not build on aix.
type Option func(*factory)

func NewFactory() extension.Factory {
	panic("aix is not supported")
}

// NewFactoryWithOptions creates a factory for the Datadog extension. Options are
// ignored: the extension is unsupported on aix.
func NewFactoryWithOptions(...Option) extension.Factory {
	return NewFactory()
}
