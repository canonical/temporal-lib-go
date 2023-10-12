package encryption_test

import (
	"testing"

	"github.com/canonical/temporal-lib-go/encryption"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/converter"
)

func Test_DataConverter(t *testing.T) {
	defaultDc := converter.GetDefaultDataConverter()

	cryptDc, err := encryption.NewEncryptionDataConverter(
		converter.GetDefaultDataConverter(),
		encryption.EncryptionOptions{
			Key: "HLCeMJLLiyLrUOukdThNgRfyraIXZk918rtp5VX/uwI=",
		},
	)
	require.NoError(t, err)

	defaultPayloads, err := defaultDc.ToPayloads("Testing")
	require.NoError(t, err)

	encryptedPayloads, err := cryptDc.ToPayloads("Testing")
	require.NoError(t, err)

	require.NotEqual(t, defaultPayloads.Payloads[0].GetData(), encryptedPayloads.Payloads[0].GetData())

	var result string
	err = cryptDc.FromPayloads(encryptedPayloads, &result)
	require.NoError(t, err)

	require.Equal(t, "Testing", result)
}
