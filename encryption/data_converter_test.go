package encryption_test

import (
	"testing"

	"github.com/canonical/temporal-lib-go/encryption"
	"github.com/go-quicktest/qt"
	"go.temporal.io/sdk/converter"
)

func TestDataConverter(t *testing.T) {
	defaultDc := converter.GetDefaultDataConverter()

	cryptDc, err := encryption.NewEncryptionDataConverter(
		converter.GetDefaultDataConverter(),
		encryption.EncryptionOptions{
			Key: "HLCeMJLLiyLrUOukdThNgRfyraIXZk918rtp5VX/uwI=",
		},
	)
	qt.Assert(t, qt.IsNil(err))

	defaultPayloads, err := defaultDc.ToPayloads("Testing")
	qt.Assert(t, qt.IsNil(err))

	encryptedPayloads, err := cryptDc.ToPayloads("Testing")
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.Not(qt.Equals(
		defaultPayloads.Payloads[0].GetData(),
		encryptedPayloads.Payloads[0].GetData(),
	)))

	var result string
	err = cryptDc.FromPayloads(encryptedPayloads, &result)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals("Testing", result))
}
