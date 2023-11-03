package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/httpbakery"
	"gopkg.in/macaroon-bakery.v2/httpbakery/agent"
	"gopkg.in/macaroon.v2"
	"gopkg.in/yaml.v2"
)

const (
	candidProvider string = "candid"
	googleProvider string = "google"
	groupScope     string = "https://www.googleapis.com/auth/admin.directory.group.readonly"
)

// MacaroonHeadersProvider implements go.temporal.io/sdk/client/internal.HeadersProvider
// to customize the authorization header when connecting to Temporal instance
// backed up by Candid auth.
type MacaroonHeadersProvider struct {
	bakeryClient *httpbakery.Client
	authOptions  *MacaroonAuthOptions
	// ms holds the discharged macaroon in memory while it's still valid (not
	// expired).
	ms macaroon.Slice
	mu sync.Mutex
}

// GoogleHeadersProvider implements go.temporal.io/sdk/client/internal.HeadersProvider
// to customize the authorization header when connecting to Temporal instance
// backed up by Google IAM auth.
type GoogleHeadersProvider struct {
	authOptions *GoogleAuthOptions
	// token holds the access token in memory while it's still valid (not expired).
	token *oauth2.Token
	mu    sync.Mutex
}

// AuthOptions represents the necessary data to create a HeadersProvider for
// authentication and authorization using supported auth providers.
type AuthOptions struct {
	Provider string
	Config   any
}

// MacaroonAuthOptions represents the necessary data to create a HeadersProvider for
// authentication and authorization using Candid.
type MacaroonAuthOptions struct {
	// MacaroonURL represents the HTTP endpoint from which to fetch minted
	// macaroons.
	MacaroonURL string `yaml:"macaroon_url"`
	// AgentKey represents the agent key that will be authenticated with Candid.
	AgentKey *bakery.KeyPair `yaml:"keys"`
	// AgentKey represents the agent user name that will be authenticated with Candid.
	AgentUsername string `yaml:"username"`
}

// GoogleAuthOptions represents the necessary data to create a HeadersProvider for
// authentication and authorization using Google IAM.
type GoogleAuthOptions struct {
	// The type of authentication. Typically "service_account".
	Type string `yaml:"type"`
	// The Google Cloud project ID.
	ProjectID string `yaml:"project_id"`
	// The private key ID.
	PrivateKeyID string `yaml:"private_key_id"`
	// The private key associated with the service account.
	PrivateKey string `yaml:"private_key"`
	// The client email associated with the service account.
	ClientEmail string `yaml:"client_email"`
	// The client ID associated with the service account.
	ClientID string `yaml:"client_id"`
	// The authentication URI.
	AuthURI string `yaml:"auth_uri"`
	// The token URI.
	TokenURI string `yaml:"token_uri"`
	// The URL of the authentication provider's x.509 certificate.
	AuthProviderCertURL string `yaml:"auth_provider_x509_cert_url"`
	// The URL of the client's x.509 certificate.
	ClientCertURL string `yaml:"client_x509_cert_url"`
}

// HeadersProvider returns a map of gRPC headers that should be used on every request.
type HeadersProvider interface {
	GetHeaders(ctx context.Context) (map[string]string, error)
}

// GetHeaders returns a map overwriting the authorization header.
func (h *GoogleHeadersProvider) GetHeaders(ctx context.Context) (map[string]string, error) {
	token, err := h.getGoogleAccessToken(ctx)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return map[string]string{"authorization": "Bearer " + token.AccessToken}, nil
}

// getGoogleAccessToken returns a Google IAM access token to be used for
// authorization with the Temporal Server.
//
// It also caches the token in memory, for as long as it is valid, such that
// subsequent calls to this function do not perform an auth dance every single
// time.
func (h *GoogleHeadersProvider) getGoogleAccessToken(ctx context.Context) (*oauth2.Token, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.token != nil && h.token.Valid() {
		return h.token, nil
	}

	serviceAccountJSON, err := convertYAMLStructToEncodedJSON(&h.authOptions)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	credentials, err := google.CredentialsFromJSON(ctx, serviceAccountJSON, "email", "profile", "openid", groupScope)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	h.token, err = credentials.TokenSource.Token()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return h.token, nil
}

// GetHeaders returns a map overwriting the authorization header.
func (h *MacaroonHeadersProvider) GetHeaders(ctx context.Context) (map[string]string, error) {
	ms, err := h.getDischargedMacaroon(ctx)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	buf, err := ms.MarshalBinary()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	headerMacaroon := base64.RawURLEncoding.EncodeToString(buf)
	return map[string]string{"authorization": "Macaroon " + headerMacaroon}, nil
}

// getDischargedMacaroon returns a discharged macaroon to be used for
// authorization with the Temporal Server. It fetches a macaroon from the Server
// and discharges it against the auth provider specified in it.
//
// It also caches the macaroon in memory, for as long as it is valid, such that
// subsequent calls to this function do not perform an auth dance every single
// time.
func (h *MacaroonHeadersProvider) getDischargedMacaroon(ctx context.Context) (macaroon.Slice, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.ms != nil {
		expiry, found := checkers.MacaroonsExpiryTime(nil, h.ms)
		if !found || time.Now().Before(expiry) {
			return h.ms, nil
		}
	}

	resp, err := h.bakeryClient.Get(h.authOptions.MacaroonURL)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	json, err := base64.RawURLEncoding.DecodeString(string(body))
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var m bakery.Macaroon
	if err = m.UnmarshalJSON(json); err != nil {
		return nil, errgo.Mask(err)
	}

	caveats := m.M().Caveats()
	if len(caveats) == 0 {
		return nil, errgo.Newf("macaroon missing required caveat")
	}
	authURL := caveats[0].Location

	if err := agent.SetUpAuth(h.bakeryClient, &agent.AuthInfo{
		Key: h.authOptions.AgentKey,
		Agents: []agent.Agent{{
			URL:      authURL,
			Username: h.authOptions.AgentUsername,
		}},
	}); err != nil {
		return nil, errgo.Mask(err)
	}
	h.ms, err = h.bakeryClient.DischargeAll(ctx, &m)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return h.ms, nil
}

// NewAuthHeadersProvider creates an implementation of the HeadersProvider
// interface based on the provided AuthOptions.
func NewAuthHeadersProvider(opts *AuthOptions) (HeadersProvider, error) {
	structBytes, err := yaml.Marshal(opts.Config)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	if opts.Provider == candidProvider {
		macaroonHeadersProvider, err := NewMacaroonHeadersProvider(structBytes)
		if err != nil {
			return nil, errgo.Mask(err)
		}

		return macaroonHeadersProvider, nil
	}

	if opts.Provider == googleProvider {
		googleHeadersProvider, err := NewGoogleHeadersProvider(structBytes)
		if err != nil {
			return nil, errgo.Mask(err)
		}

		return googleHeadersProvider, nil
	}

	return nil, errgo.Mask(errors.New("auth provider not supported. please specify 'candid' or 'google'"))
}

// NewMacaroonHeadersProvider returns a new MacaroonHeadersProvider instance.
func NewMacaroonHeadersProvider(configBytes []byte) (HeadersProvider, error) {
	var macaroonOpts MacaroonAuthOptions
	if err := yaml.Unmarshal(configBytes, &macaroonOpts); err != nil {
		return nil, errgo.Mask(err)
	}

	bakeryClient := httpbakery.NewClient()
	return &MacaroonHeadersProvider{
		bakeryClient: bakeryClient,
		authOptions:  &macaroonOpts,
	}, nil
}

// NewGoogleheadersProvider returns a new GoogleHeadersProvider instance.
func NewGoogleHeadersProvider(configBytes []byte) (HeadersProvider, error) {
	var googleOpts GoogleAuthOptions
	if err := yaml.Unmarshal(configBytes, &googleOpts); err != nil {
		return nil, errgo.Mask(err)
	}

	return &GoogleHeadersProvider{
		authOptions: &googleOpts,
	}, nil
}

// convertYAMLStructToEncodedJSON converts a YAML-encoded struct to JSON.
func convertYAMLStructToEncodedJSON(s interface{}) ([]byte, error) {
	yamlValue, err := yaml.Marshal(s)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var jsonData map[string]string
	if err := yaml.Unmarshal(yamlValue, &jsonData); err != nil {
		return nil, errgo.Mask(err)
	}

	encodedJSON, err := json.Marshal(jsonData)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return encodedJSON, nil
}
