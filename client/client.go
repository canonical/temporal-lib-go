package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/canonical/temporal-lib-go/auth"
	"github.com/canonical/temporal-lib-go/encryption"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
)

// Options allows to specify various configurations when connecting to Temporal.
type Options struct {
	client.Options
	HostPort   string                        `yaml:"host"`
	Namespace  string                        `yaml:"namespace"`
	Queue      string                        `yaml:"queue"`
	Auth       *auth.AuthOptions             `yaml:"auth"`
	Encryption *encryption.EncryptionOptions `yaml:"encryption"`
	TLSRootCAs string                        `yaml:"tls_root_cas"`
}

func (t *Options) GetTLSRootCAs() (*x509.CertPool, error) {
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM([]byte(t.TLSRootCAs)) {
		return nil, fmt.Errorf("invalid TLS root ca")
	}

	return cp, nil
}

// Dial offers a wrapper over Temporal SDK's Dial() that offers Candid auth,
// Google auth and encryption readily available, if enabled through the options.
func Dial(options Options) (client.Client, error) {
	clientOptions, err := configureOptions(options)
	if err != nil {
		return nil, err
	}

	return client.Dial(clientOptions)
}

// NewLazyClient offers a wrapper over Temporal SDK's NewLazyClient() that
// offers Candid auth, Google auth and encryption readily available, if enabled
// through the options. Unlike Dial, this will not eagerly connect to the
// server.
func NewLazyClient(options Options) (client.Client, error) {
	clientOptions, err := configureOptions(options)
	if err != nil {
		return nil, err
	}

	return client.NewLazyClient(clientOptions)
}

func configureOptions(options Options) (client.Options, error) {
	hostPort := strings.Split(options.HostPort, ":")
	// If no port is specified, assume default TLS HTTP port.
	if len(hostPort) == 1 {
		options.HostPort = fmt.Sprintf("%s:443", options.HostPort)
	}

	options.Options.HostPort = options.HostPort
	options.Options.Namespace = options.Namespace

	if options.Auth != nil {
		hp, err := auth.NewAuthHeadersProvider(options.Auth)
		if err != nil {
			return client.Options{}, err
		}
		options.HeadersProvider = hp
	}

	if options.Encryption != nil {
		var err error
		options.DataConverter, err = encryption.NewEncryptionDataConverter(
			converter.GetDefaultDataConverter(),
			*options.Encryption,
		)
		if err != nil {
			return client.Options{}, err
		}
		options.ContextPropagators = []workflow.ContextPropagator{encryption.NewContextPropagator()}
	}

	if options.TLSRootCAs != "" {
		rootCA, err := options.GetTLSRootCAs()
		if err != nil {
			return client.Options{}, err
		}
		serverName := hostPort[0]
		options.ConnectionOptions.TLS = &tls.Config{
			ServerName: serverName,
			RootCAs:    rootCA,
		}
	}

	return options.Options, nil
}
