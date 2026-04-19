# passage-webauthn

[![Release](https://img.shields.io/github/v/release/rozd/passage-webauthn)](https://github.com/rozd/passage-webauthn/releases)
[![Swift 6.0](https://img.shields.io/badge/Swift-6.0-orange.svg)](https://swift.org)
[![License](https://img.shields.io/github/license/rozd/passage-webauthn)](LICENSE)

WebAuthn passkey implementation for [Passage](https://github.com/vapor-community/passage) authentication framework.

This package provides a bridge between Passage and [webauthn-swift](https://github.com/swift-server/webauthn-swift), enabling passwordless passkey authentication (registration and assertion) backed by the W3C WebAuthn standard.

> **Note:** This package cannot be used standalone. It requires both [Passage](https://github.com/vapor-community/passage) and [webauthn-swift](https://github.com/swift-server/webauthn-swift) packages to function.

## Installation

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/rozd/passage-webauthn.git", from: "0.0.1"),
]
```

Then add `PassageWebAuthn` to your target dependencies:

```swift
.target(
    name: "App",
    dependencies: [
        .product(name: "PassageWebAuthn", package: "passage-webauthn"),
    ]
)
```

## Configuration

Configure `WebAuthnPasskeyService` with your relying-party details:

```swift
import Passage
import PassageWebAuthn
import WebAuthn

let passkeyService = WebAuthnPasskeyService(
    configuration: .init(
        relyingPartyID: "example.com",
        relyingPartyName: "My App",
        relyingPartyOrigin: "https://example.com"
    )
)
```

Then pass it to Passage during configuration:

```swift
app.passage.configure(
    services: .init(
        passkeyService: passkeyService,
        // ... other services
    ),
    configuration: .init(
        passkey: .init(
            policy: .init(
                userVerification: .required,
                attestation: .none,
                timeout: 60,
                supportedAlgorithms: [.algES256, .algRS256]
            )
        ),
        // ... other configuration
    )
)
```

## How It Works

PassageWebAuthn implements the four-step WebAuthn ceremony on behalf of Passage:

| Step | Method | Description |
|------|--------|-------------|
| 1 | `beginRegistration` | Generates `PublicKeyCredentialCreationOptions` and a short-lived challenge |
| 2 | `finishRegistration` | Verifies attestation, extracts the new credential, and maps it to a `PasskeyCredential` |
| 3 | `beginAuthentication` | Generates `PublicKeyCredentialRequestOptions` and a short-lived challenge |
| 4 | `finishAuthentication` | Verifies the assertion signature and returns updated sign-count and backup state |

Challenges are managed by Passage core (stored and looked up via the `lookupChallenge` callback); this package only handles the cryptographic verification layer.

## Relying Party Configuration

| Parameter | Description |
|-----------|-------------|
| `relyingPartyID` | Your domain (e.g. `example.com`). Must match the origin without scheme or port. |
| `relyingPartyName` | Human-readable app name shown by the authenticator UI. |
| `relyingPartyOrigin` | Full origin of your app (e.g. `https://example.com`). |

## Passkey Policy

The `Passage.Configuration.Passkey.Policy` passed to each method controls:

| Option | Values | Description |
|--------|--------|-------------|
| `userVerification` | `.required`, `.preferred`, `.discouraged` | Whether PIN/biometric is required |
| `attestation` | `.none`, `.indirect`, `.direct`, `.enterprise` | Attestation conveyance preference |
| `timeout` | `TimeInterval` | Browser ceremony timeout in seconds |
| `supportedAlgorithms` | `[COSEAlgorithmIdentifier]` | Accepted public key algorithms (e.g. `.algES256`, `.algRS256`) |

## Requirements

- Swift 6.0+
- macOS 13+ / Linux
- Vapor 4.119+
- webauthn-swift 1.0.0-beta.1+

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
