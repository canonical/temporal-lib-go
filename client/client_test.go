package client

import (
	"encoding/base64"
	"testing"

	"github.com/canonical/temporal-lib-go/auth"
	"github.com/canonical/temporal-lib-go/encryption"
	"github.com/stretchr/testify/require"
	sdkclient "go.temporal.io/sdk/client"
)

func TestNewLazyClientDoesNotConnect(t *testing.T) {
	client, err := NewLazyClient(Options{
		HostPort:  "127.0.0.1:1",
		Namespace: "test",
		Encryption: &encryption.EncryptionOptions{
			Key:      base64.StdEncoding.EncodeToString(make([]byte, 16)),
			Compress: true,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, client)
	client.Close()
}

func TestConfigureOptions(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	options, err := configureOptions(Options{
		Options: sdkclient.Options{
			Identity: "test-identity",
		},
		HostPort:  "temporal.example.com",
		Namespace: "test-namespace",
		Auth: &auth.AuthOptions{
			Provider: "google",
			Config:   auth.GoogleAuthOptions{},
		},
		Encryption: &encryption.EncryptionOptions{Key: key},
	})
	require.NoError(t, err)
	require.Equal(t, "temporal.example.com:443", options.HostPort)
	require.Equal(t, "test-namespace", options.Namespace)
	require.Equal(t, "test-identity", options.Identity)
	require.IsType(t, &auth.GoogleHeadersProvider{}, options.HeadersProvider)
	require.IsType(t, &encryption.EncryptionDataConverter{}, options.DataConverter)
	require.Len(t, options.ContextPropagators, 1)
}

func TestNewLazyClientValidatesOptions(t *testing.T) {
	tests := []struct {
		name    string
		options Options
		err     string
	}{{
		name: "invalid authentication provider",
		options: Options{
			Auth: &auth.AuthOptions{Provider: "invalid"},
		},
		err: "auth provider not supported. please specify 'candid' or 'google'",
	}, {
		name: "invalid encryption key",
		options: Options{
			Encryption: &encryption.EncryptionOptions{Key: "invalid"},
		},
		err: "illegal base64 data at input byte 4",
	}, {
		name: "invalid TLS root CA",
		options: Options{
			TLSRootCAs: "invalid",
		},
		err: "invalid TLS root ca",
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewLazyClient(test.options)
			require.EqualError(t, err, test.err)
			require.Nil(t, client)
		})
	}
}
