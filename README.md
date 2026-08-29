# kmip-go — KMIP 2.1 Go client for Eviden KMS

[![Go](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev)
[![Module](https://img.shields.io/badge/module-github.com%2FCosmian%2Fkmip--go-blue)](https://github.com/Cosmian/kmip-go)
[![KMS](https://img.shields.io/badge/ghcr.io%2Fcosmian%2Fkms-5.26.0-green)](https://github.com/Cosmian/kms/pkgs/container/kms)

A minimal, zero-external-dependency KMIP 2.1 JSON TTLV HTTP client for
[Eviden KMS](https://github.com/Cosmian/kms).

---

## Quick start

```go
import "github.com/Cosmian/kmip-go"

// mTLS (recommended for production)
c, _ := kmip.NewClient(&kmip.Config{
    KMSAddr:    "https://kms.example.com:9998",
    CACertPath: "/etc/kms/ca.crt",
    CertAuth: &kmip.CertAuthConfig{
        ClientCertPath: "/etc/kms/client.crt",
        ClientKeyPath:  "/etc/kms/client.key",
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
    unit                go vet + gofmt + go test -race
  testdata/certs/       mTLS test certificates (committed; regen: scripts/generate-test-certs.sh)
  testdata/kms-mtls.toml KMS config for mTLS docker-compose service
  scripts/
    generate-test-certs.sh  Regenerate testdata/certs/ when they expire
```

---

## API reference

| Function | KMIP operation | Notes |
|---|---|---|
| `NewClient(cfg)` | — | mTLS (`cert_auth`) or token (`token_auth`) |
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
# or:
mise run test:unit
```

### Live integration tests — no-auth

```bash
mise run test:live
```

### Live integration tests — mTLS

```bash
# Regenerate certs when they expire (10-year validity; already committed)
bash scripts/generate-test-certs.sh

mise run test:live --mtls
```

---

## Docker images (pinned in `docker-compose.yml`)

| Service | Image | Auth |
|---|---|---|
| `kms` | `ghcr.io/cosmian/kms:5.26.0` | No-auth, plain HTTP |
| `kms-mtls` | `ghcr.io/cosmian/kms:5.26.0` | mTLS HTTPS (`clients_ca_cert_file = ca.crt`) |

---

## License

Business Source License 1.1 — see [LICENSE](LICENSE) in the parent KMS repository.
