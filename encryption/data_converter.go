package encryption

import (
	"encoding/base64"
	"errors"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
)

const (
	// MetadataEncodingEncrypted is "binary/encrypted"
	MetadataEncodingEncrypted = "binary/encrypted"
)

type EncryptionDataConverter struct {
	converter.DataConverter
	// Until EncodingDataConverter supports workflow.ContextAware we'll store parent here.
	parent  converter.DataConverter
	options EncryptionOptions
}

type EncryptionOptions struct {
	Key string `yaml:"key"`
	// Enable ZLib compression before encryption.
	Compress bool `yaml:"compress"`
}

// Codec implements PayloadCodec using AES Crypt.
type Codec struct {
	Key []byte
}

// NewEncryptionDataConverter creates a new instance of EncryptionDataConverter wrapping a DataConverter
func NewEncryptionDataConverter(dataConverter converter.DataConverter, options EncryptionOptions) (*EncryptionDataConverter, error) {
	byteKey, err := base64.StdEncoding.DecodeString(options.Key)
	if err != nil {
		return nil, err
	}
	if len(byteKey) != 8 && len(byteKey) != 16 && len(byteKey) != 32 {
		return nil, errors.New("encryption key must be 8, 16 or 32 bytes long")
	}

	codecs := []converter.PayloadCodec{
		&Codec{Key: byteKey},
	}
	// Enable compression if requested.
	// Note that this must be done before encryption to provide any value. Encrypted data should by design not compress very well.
	// This means the compression codec must come after the encryption codec here as codecs are applied last -> first.
	if options.Compress {
		codecs = append(codecs, converter.NewZlibCodec(converter.ZlibCodecOptions{AlwaysEncode: true}))
	}

	return &EncryptionDataConverter{
		parent:        dataConverter,
		DataConverter: converter.NewCodecDataConverter(dataConverter, codecs...),
		options:       options,
	}, nil
}

// Encode implements converter.PayloadCodec.Encode.
func (e *Codec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	result := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		origBytes, err := p.Marshal()
		if err != nil {
			return payloads, err
		}

		b, err := encrypt(origBytes, e.Key)
		if err != nil {
			return payloads, err
		}

		result[i] = &commonpb.Payload{
			Metadata: map[string][]byte{
				converter.MetadataEncoding: []byte(MetadataEncodingEncrypted),
			},
			Data: b,
		}
	}

	return result, nil
}

// Decode implements converter.PayloadCodec.Decode.
func (e *Codec) Decode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	result := make([]*commonpb.Payload, len(payloads))
	for i, p := range payloads {
		// Only if it's encrypted
		if string(p.Metadata[converter.MetadataEncoding]) != MetadataEncodingEncrypted {
			result[i] = p
			continue
		}

		b, err := decrypt(p.Data, e.Key)
		if err != nil {
			return payloads, err
		}

		result[i] = &commonpb.Payload{}
		err = result[i].Unmarshal(b)
		if err != nil {
			return payloads, err
		}
	}

	return result, nil
}
