# kmip-go — KMIP 2.1 Go client for Eviden KMS + SPIRE plugins

[![Go](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev)
[![Module](https://img.shields.io/badge/module-github.com%2FCosmian%2Fkmip--go-blue)](https://github.com/Cosmian/kmip-go)
[![KMS](https://img.shields.io/badge/ghcr.io%2Fcosmian%2Fkms-5.26.0-green)](https://github.com/Cosmian/kms/pkgs/container/kms)
[![SPIRE PR](https://img.shields.io/badge/SPIRE%20PR-issue%20%237233-orange)](https://github.com/spiffe/spire/issues/7233)

A minimal, zero-external-dependency **KMIP 2.1 JSON TTLV client** for
[Eviden KMS](https://github.com/Cosmian/kms), plus **built-in SPIRE plugins**
(`eviden_kms` KeyManager and UpstreamAuthority) that let SPIRE store its signing
keys and sign its intermediate CA directly via KMIP 2.1 — no Vault-compatible
layer, no auth-verifier.

---

## Quick start

```go
import "github.com/Cosmian/kmip-go"

// mTLS (recommended for production)
c, _ := kmip.NewClient(&kmip.Config{
    KMSAddr:    "https://kms.example.com:9998",
    CACertPath: "/etc/kms/ca.crt",
    CertAuth: &kmip.CertAuthConfig{
        ClientCertPath: "/etc/kms/spire-client.crt",
        ClientKeyPath:  "/etc/kms/spire-client.key",
    },
})

// Create an EC P-256 key pair
kp, _ := c.CreateKeyPair(ctx, kmip.KeyTypeECP256, []string{"my-key"})

// Sign pre-hashed data
sig, _ := c.Sign(ctx, kp.PrivateKeyUID, digest, kmip.HashSHA256, kmip.SigECDSA)
```

For no-auth / API token auth:
```go
c, _ := kmip.NewClient(&kmip.Config{
    KMSAddr:   "http://localhost:9998",
    TokenAuth: &kmip.TokenAuthConfig{Token: os.Getenv("KMS_API_TOKEN")},
})
```

---

## Repository structure

```
kmip-go/
  *.go                  Go package (client, operations, fake, ttlv…)
  go.mod                module github.com/Cosmian/kmip-go, go 1.26
  integration_test.go   Live tests against a real KMS (build tag: integration)
  docker-compose.yml    Pinned image versions (ghcr.io/cosmian/kms:5.26.0)
  .mise.toml            mise task runner config
  .mise/tasks/test/
    live                Docker KMS + go test -tags integration (no-auth or mTLS)
    spire-e2e           Docker KMS + SPIRE server from submodule (mTLS)
  spire/                Git submodule → spiffe/spire@feature/eviden-kms-plugins
  test_data/            Git submodule → Cosmian/test_data@spire_sds
  docs/                 mdBook documentation
```

---

## API reference

| Function | KMIP operation | Notes |
|---|---|---|
| `NewClient(cfg)` | — | mTLS (`cert_auth`) or Bearer token (`token_auth`) |
| `CreateKeyPair(ctx, KeyType, tags)` | `CreateKeyPair` | EC-P256/P384, RSA-2048/4096; FIPS usage masks |
| `GetPublicKey(ctx, pubKeyUID)` | `Get(PKCS8)` | Returns DER-encoded PKIX public key |
| `Locate(ctx, tags)` | `Locate` | Finds private keys by cosmian vendor tag |
| `Sign(ctx, uid, data, hash, sig)` | `Sign(DigestedData)` | ECDSA / RSA-PKCS1 / RSA-PSS |
| `Destroy(ctx, uid)` | `Revoke` + `Destroy` | KMIP requires Revoke before Destroy for Active keys |
| `Certify(ctx, csr, caKey, caCert, ext)` | `Certify` | CSR PEM → signed certificate |
| `CreateSelfSignedCertificate(ctx, pubKeyUID, cn, ext)` | `Certify` | Sets `CertificateLink` on public key |
| `ExportCertificate(ctx, certUID)` | `Get` | Returns certificate PEM bytes |
| `GetLinkedCertificateUID(ctx, privKeyUID)` | `GetAttributes` | Two-step: priv → pub → cert |
| `GetLinkedPublicKeyUID(ctx, privKeyUID)` | `GetAttributes` | Follows `PublicKeyLink` |
| `GetVendorTags(ctx, uid)` | `GetAttributes` | Reads cosmian vendor tag array |
| `AddTags(ctx, uid, tags)` | `SetAttribute` | Appends vendor tags to an object |
| `CAExtension` | — | `[]byte` const: `[v3_ca]\nbasicConstraints=critical,CA:TRUE\n...` |
| `FakeKMS` | — | Exported `httptest.Server` for unit testing |

---

## Running tests

### Unit tests (no KMS required)

```bash
go test ./...
```

### Live integration tests — no-auth

Uses `ghcr.io/cosmian/kms:5.26.0` via Docker Compose:

```bash
mise run test:live
```

### Live integration tests — mTLS

Starts the KMS with `clients_ca_cert_file` enforcing mutual TLS:

```bash
# Regenerate certs first if needed
bash test_data/spire/certs/generate-test-certs.sh

mise run test:live --mtls
```

### SPIRE end-to-end test (mTLS)

Builds `spire-server` from the `spire/` submodule, starts the Docker KMS with mTLS,
provisions a root CA, starts SPIRE, and verifies healthcheck + key presence in KMS:

```bash
mise run test:spire-e2e
```

Expected output:
```
[OK] spire-server built
[OK] KMS (mTLS) ready at https://127.0.0.1:9998
[OK] CA key pair + self-signed cert provisioned
[OK] SPIRE server is healthy — eviden_kms KeyManager + UpstreamAuthority with mTLS verified.
[OK] Found 2 key(s) in KMS for SPIRE server 'spire-e2e-server' — mTLS KeyManager verified.
[OK] All checks passed.
```

---

## SPIRE plugins

The `spire/` submodule contains two built-in SPIRE plugins:

| Plugin | Package | What it does |
|---|---|---|
| `KeyManager "eviden_kms"` | `pkg/server/plugin/keymanager/evidenkms` | Creates/signs/recovers SPIRE signing keys in KMS via KMIP |
| `UpstreamAuthority "eviden_kms"` | `pkg/server/plugin/upstreamauthority/evidenkms` | Signs SPIRE's intermediate CA CSR via KMIP `Certify` |

Both plugins use this module (`github.com/Cosmian/kmip-go`) and support mTLS
authentication to the KMS.

See `test_data/spire/config/spire-server-kmip-a.conf` for a complete SPIRE
server configuration example with `cert_auth`.

A PR to upstream SPIRE is tracked at
[spiffe/spire#7233](https://github.com/spiffe/spire/issues/7233).

---

## Docker images (pinned in `docker-compose.yml`)

| Service | Image | Auth |
|---|---|---|
| `kms` | `ghcr.io/cosmian/kms:5.26.0` | No-auth, plain HTTP |
| `kms-mtls` | `ghcr.io/cosmian/kms:5.26.0` | mTLS HTTPS (`clients_ca_cert_file = ca.crt`) |

---

## License

Business Source License 1.1 — see [LICENSE](LICENSE) in the parent KMS repository.
