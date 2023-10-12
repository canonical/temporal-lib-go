# temporal-lib-go

This library provides a wrapper for the _Client.connect_ method from
[temporalio/sdk-go](https://github.com/temporalio/sdk-go) candid-based
authentication, Google IAM-based authentication and encryption.

## Usage

The following code shows how a client connection is created using by using the
original (vanilla) temporalio sdk:

```go
import "go.temporal.io/sdk/client"
func main() {
    opts := client.Options{
      HostPort: "localhost:7233"
      ...
    }
    c, err := client.Dial(opts)
    if err != nil {
        log.Fatalln("unable to create Temporal client", err)
    }
    defer c.Close()
    ...
}
```

In order to add authorization and encryption capabilities to this client we
replace the connect call as follows:

### Candid-based authorization

```go
import "github.com/canonical/temporal-lib-go/client"
import "github.com/canonical/temporal-lib-go/auth"
import "gopkg.in/macaroon-bakery.v2/bakery"

func main() {
    var privateKey bakery.Key
    privateKey.UnmarshalText([]byte("PRIVATE_KEY"))

    var publicKey bakery.Key
    publicKey.UnmarshalText([]byte("PUBLIC_KEY"))

    opts := client.Options{
      HostPort: "localhost:7233",
      Namespace: "test",
      Queue: "test-queue",
      Auth: &auth.AuthOptions {
        Provider: "candid",
        Config: auth.MacaroonAuthOptions{
          MacaroonURL: "...",
          AgentUsername: "...",
          AgentKey: &bakery.KeyPair{
            Private: bakery.PrivateKey{Key: privateKey},
            Public: bakery.PublicKey{Key: publicKey},
          },
        },
      },
      TLSRootCAs: "...",
    }

    // alternatively options could be loaded from a yaml file as the one showed below
    c, err := client.Dial(opts)
    if err != nil {
        log.Fatalln("unable to create Temporal client", err)
    }
    defer c.Close()
    ...
}
```

The structure of the YAML file which can be used to construct the Options is as
following:

```yaml
host: "localhost:7233"
queue: "test-queue"
namespace: "test"
encryption:
  key: "HLCeMJLLiyLrUOukdThNgRfyraIXZk918rtp5VX/uwI="
auth:
  provider: "candid"
  config:
    macaroon_url: "http://localhost:7888/macaroon"
    username: "test"
    keys:
      private: "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg="
      public: "ODc2NTQzMjE4NzY1NDMyMTg3NjU0MzIxODc2NTQzMjE="
tls_root_cas: |
  'base64 certificate'
```

### Google IAM-based authorization

```go
import "github.com/canonical/temporal-lib-go/client"
import "github.com/canonical/temporal-lib-go/auth"

func main() {
    opts := client.Options{
      HostPort: "localhost:7233",
      Namespace: "test",
      Queue: "test-queue",
      Auth: &auth.AuthOptions {
        Provider: "google",
        Config: auth.GoogleAuthOptions{
          Type: "service_account",
          ProjectID: "...",
          PrivateKeyID: "...",
          PrivateKey: "...",
          ClientEmail: "...",
          ClientID: "...",
          AuthURI: "https://accounts.google.com/o/oauth2/auth",
          TokenURI: "https://oauth2.googleapis.com/token",
          AuthProviderCertURL: "...",
          ClientCertURL: "https://www.googleapis.com/oauth2/v1/certs",
        },
      },
      TLSRootCAs: "...",
    }

    // alternatively options could be loaded from a yaml file as the one showed below
    c, err := client.Dial(opts)
    if err != nil {
        log.Fatalln("unable to create Temporal client", err)
    }
    defer c.Close()
    ...
}
```

The structure of the YAML file which can be used to construct the Options is as
follows:

```yaml
host: "localhost:7233"
queue: "test-queue"
namespace: "test"
encryption:
  key: "HLCeMJLLiyLrUOukdThNgRfyraIXZk918rtp5VX/uwI="
auth:
  provider: "google"
  config:
    type: "service_account"
    project_id: "REPLACE_WITH_PROJECT_ID"
    private_key_id: "REPLACE_WITH_PRIVATE_KEY_ID"
    private_key: "REPLACE_WITH_PRIVATE_KEY"
    client_email: "REPLACE_WITH_CLIENT_EMAIL"
    client_id: "REPLACE_WITH_CLIENT_ID"
    auth_uri: "https://accounts.google.com/o/oauth2/auth"
    token_uri: "https://oauth2.googleapis.com/token"
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs"
    client_x509_cert_url: "REPLACE_WITH_CLIENT_CERT_URL"
tls_root_cas: |
  'base64 certificate'
```

## Samples

More examples of workflows using this library can be found here:

- [temporalio/samples-go](https://github.com/temporalio/samples-go)
