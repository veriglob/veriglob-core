# HSM Integration Guide

This guide covers the optional Hardware Security Module (HSM) integration for secure key storage in Veriglob wallets.

## Overview

Veriglob supports two key storage modes:

| Mode | Security Level | Use Case |
|------|----------------|----------|
| **Software** | Standard | Development, testing, personal wallets |
| **HSM** | FIPS 140-2 Level 3 | Enterprise, regulatory compliance, high-value credentials |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Wallet                           │
├─────────────────────────────────────────────────────────┤
│                    KeyProvider Interface                │
├───────────────────────┬─────────────────────────────────┤
│  SoftwareKeyProvider  │       HSMKeyProvider            │
│  (in-memory keys)     │       (PKCS#11)                 │
└───────────────────────┴─────────────────────────────────┘
```

The `KeyProvider` interface abstracts key operations, allowing seamless switching between software and hardware-backed keys.

## KeyProvider Interface

```go
type KeyProvider interface {
    Type() KeyProviderType
    GenerateKey() (publicKey ed25519.PublicKey, keyID string, err error)
    ImportKey(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (keyID string, err error)
    GetPublicKey(keyID string) (ed25519.PublicKey, error)
    Sign(keyID string, data []byte) (signature []byte, err error)
    DeleteKey(keyID string) error
    Close() error
}
```

## Software Key Provider

The default provider stores keys in memory with mutex protection for concurrent access.

### Usage

```go
import "github.com/veriglob/veriglob-core/internal/storage"

// Create software key provider
provider := storage.NewSoftwareKeyProvider()

// Create wallet with provider
opts := &storage.WalletOptions{
    KeyProvider: provider,
}
wallet, err := storage.CreateWalletWithOptions(path, mnemonic, opts)

// Generate keys
err = wallet.GenerateKeys("did:key:example")

// Sign data
signature, err := wallet.Sign([]byte("data to sign"))
```

### Without KeyProvider (Default)

When no `KeyProvider` is specified, the wallet derives keys directly from the mnemonic:

```go
// Simple wallet creation (keys derived from mnemonic)
wallet, err := storage.CreateWallet(path, mnemonic)
err = wallet.GenerateKeys("did:key:example")
```

## HSM Key Provider

For production environments requiring FIPS 140-2 compliance, use the HSM provider with PKCS#11.

### Building with HSM Support

HSM support requires the `hsm` build tag:

```bash
# Without HSM (default) - smaller binary, HSM returns ErrHSMNotAvailable
go build ./...

# With HSM support - includes PKCS#11 implementation
go build -tags hsm ./...
```

### Supported HSMs

Any PKCS#11 compatible HSM:

- **Thales Luna** - Enterprise HSM
- **AWS CloudHSM** - Cloud-based HSM
- **Azure Dedicated HSM** - Cloud-based HSM
- **YubiHSM 2** - Compact HSM
- **SoftHSM** - Software HSM for testing

### Configuration

```go
import "github.com/veriglob/veriglob-core/internal/storage"

config := storage.HSMConfig{
    LibraryPath: "/usr/local/lib/softhsm/libsofthsm2.so",
    SlotID:      0,
    PIN:         "1234",
    Label:       "veriglob-keys",  // Optional: key label prefix
}

provider, err := storage.NewHSMKeyProvider(config)
if err != nil {
    log.Fatal(err)
}
defer provider.Close()

// Create wallet with HSM
opts := &storage.WalletOptions{
    KeyProvider: provider,
}
wallet, err := storage.CreateWalletWithOptions(path, mnemonic, opts)
```

### HSM Configuration Options

| Field | Type | Description |
|-------|------|-------------|
| `LibraryPath` | string | Path to PKCS#11 library (.so/.dylib/.dll) |
| `SlotID` | uint | HSM slot number |
| `PIN` | string | User PIN for authentication |
| `Label` | string | Optional key label prefix |

### Key Properties in HSM

Keys generated in HSM have these properties:

- `CKA_TOKEN: true` - Persistent storage
- `CKA_PRIVATE: true` - Requires authentication
- `CKA_SENSITIVE: true` - Cannot be revealed in plaintext
- `CKA_EXTRACTABLE: false` - Cannot be exported
- `CKA_SIGN: true` - Can be used for signing

## Testing with SoftHSM

SoftHSM provides a software implementation of PKCS#11 for development and testing.

### Installation

```bash
# macOS
brew install softhsm

# Ubuntu/Debian
apt install softhsm2

# CentOS/RHEL
yum install softhsm
```

### Setup

```bash
# Initialize a token
softhsm2-util --init-token --slot 0 --label "veriglob" --pin 1234 --so-pin 0000

# Find library path
# macOS: /usr/local/lib/softhsm/libsofthsm2.so
# Linux: /usr/lib/softhsm/libsofthsm2.so or /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

### Test Code

```go
func TestWithSoftHSM(t *testing.T) {
    provider, err := storage.NewHSMKeyProvider(storage.HSMConfig{
        LibraryPath: "/usr/local/lib/softhsm/libsofthsm2.so",
        SlotID:      0,
        PIN:         "1234",
    })
    if err == storage.ErrHSMNotAvailable {
        t.Skip("HSM not available (build with -tags hsm)")
    }
    if err != nil {
        t.Fatal(err)
    }
    defer provider.Close()

    // Generate key in HSM
    pub, keyID, err := provider.GenerateKey()
    if err != nil {
        t.Fatal(err)
    }

    // Sign data (signing happens inside HSM)
    signature, err := provider.Sign(keyID, []byte("test data"))
    if err != nil {
        t.Fatal(err)
    }

    // Verify signature
    if !ed25519.Verify(pub, []byte("test data"), signature) {
        t.Error("signature verification failed")
    }
}
```

## Wallet Persistence

When using a KeyProvider, the wallet stores:

- **Public key** - In the encrypted wallet file
- **Key ID** - Reference to the key in the provider
- **Provider type** - "software" or "hsm"

The private key is **never** stored in the wallet file when using HSM.

### Reopening a Wallet

```go
// Must provide the same KeyProvider type when reopening
provider, _ := storage.NewHSMKeyProvider(config)
opts := &storage.WalletOptions{
    KeyProvider: provider,
}

wallet, err := storage.OpenWalletWithOptions(path, mnemonic, opts)
if err != nil {
    // Returns error if provider type doesn't match
    log.Fatal(err)
}
```

## Security Considerations

### Software Provider

- Keys stored in process memory
- Vulnerable to memory dumps
- Suitable for development and low-risk scenarios

### HSM Provider

- Private keys never leave the HSM
- Signing operations performed inside secure hardware
- Tamper-evident/tamper-resistant hardware
- Audit logging of key operations
- FIPS 140-2 Level 3 certified (hardware dependent)

### Best Practices

1. **Use HSM for production** - Especially for issuer keys
2. **Rotate keys periodically** - HSM supports key versioning
3. **Secure PIN storage** - Use environment variables or secret managers
4. **Monitor HSM logs** - Track all key operations
5. **Backup HSM keys** - Follow vendor backup procedures

## Error Handling

```go
provider, err := storage.NewHSMKeyProvider(config)
switch err {
case nil:
    // Success
case storage.ErrHSMNotAvailable:
    // Binary not built with HSM support
    // Fallback to software provider or exit
case storage.ErrHSMSessionFailed:
    // Failed to open session (wrong PIN, slot not found, etc.)
default:
    // Other PKCS#11 errors
}
```

## Migration

### Software to HSM

```go
// 1. Open existing software wallet
wallet, _ := storage.OpenWallet(path, mnemonic)
pub, priv, _ := wallet.GetKeys()

// 2. Create HSM provider and import key
hsmProvider, _ := storage.NewHSMKeyProvider(config)
keyID, _ := hsmProvider.ImportKey(pub, priv)

// 3. Create new wallet with HSM
newOpts := &storage.WalletOptions{KeyProvider: hsmProvider}
newWallet, _ := storage.CreateWalletWithOptions(newPath, mnemonic, newOpts)
newWallet.SetKeys(pub, priv, wallet.GetDID())

// 4. Securely delete old wallet
os.Remove(path)
```

## API Reference

### SoftwareKeyProvider Methods

| Method | Description |
|--------|-------------|
| `NewSoftwareKeyProvider()` | Create new provider |
| `GenerateKey()` | Generate Ed25519 key pair |
| `ImportKey(pub, priv)` | Import existing key pair |
| `GetPublicKey(keyID)` | Retrieve public key |
| `GetPrivateKey(keyID)` | Retrieve private key (software only) |
| `Sign(keyID, data)` | Sign data |
| `DeleteKey(keyID)` | Remove key |
| `ListKeys()` | List all key IDs |
| `Close()` | Release resources |

### HSMKeyProvider Methods

| Method | Description |
|--------|-------------|
| `NewHSMKeyProvider(config)` | Create and connect to HSM |
| `GenerateKey()` | Generate key in HSM |
| `ImportKey(pub, priv)` | Import key (may wrap) |
| `GetPublicKey(keyID)` | Retrieve public key |
| `Sign(keyID, data)` | Sign inside HSM |
| `DeleteKey(keyID)` | Remove key from HSM |
| `Close()` | Close PKCS#11 session |

### Wallet Methods

| Method | Description |
|--------|-------------|
| `CreateWalletWithOptions(path, mnemonic, opts)` | Create wallet with KeyProvider |
| `OpenWalletWithOptions(path, mnemonic, opts)` | Open wallet with KeyProvider |
| `GenerateKeys(did)` | Generate keys using provider |
| `SetKeys(pub, priv, did)` | Import keys into provider |
| `Sign(data)` | Sign using provider |
| `UsesHSM()` | Check if using HSM |
| `GetKeyProvider()` | Get the KeyProvider instance |
