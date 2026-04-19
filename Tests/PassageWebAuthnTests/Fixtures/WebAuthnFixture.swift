import Foundation
import Crypto
@preconcurrency import SwiftCBOR

/// Builds valid WebAuthn ceremony payloads for happy-path tests against
/// `swift-webauthn`'s verifier. Attestation format is fixed to `"none"` so
/// we avoid building attestation certificates; that's all `WebAuthnManager`
/// currently supports out of the box.
///
/// Mirrors just enough of `swift-webauthn`'s own TestModels to keep this
/// package's tests self-contained (those TestModels live behind
/// `@testable import WebAuthn` and aren't importable from here).
enum WebAuthnFixture {
    static let rpID = "login.example.com"
    static let rpName = "Example"
    static let rpOrigin = "https://login.example.com"

    /// A registration-ceremony payload plus the key material the relying
    /// party would persist after verifying it.
    struct Registration {
        /// The P-256 key pair the authenticator generated for this credential.
        let privateKey: P256.Signing.PrivateKey
        /// Raw credential ID bytes (authenticator-generated).
        let credentialID: [UInt8]
        /// Challenge bytes the RP issued and the browser echoed.
        let challenge: [UInt8]
        /// `PublicKeyCredential` JSON body ready to POST to finishRegistration.
        let body: Data
        /// Sign count embedded in authData (0 for freshly-minted passkeys).
        let signCount: UInt32
        /// COSE-encoded public key (what finishRegistration returns for storage).
        var cosePublicKey: [UInt8] { Self.cosePublicKey(for: privateKey) }

        static func cosePublicKey(for privateKey: P256.Signing.PrivateKey) -> [UInt8] {
            let raw = privateKey.publicKey.rawRepresentation  // x || y, 64 bytes
            let x = [UInt8](raw.prefix(32))
            let y = [UInt8](raw.suffix(32))
            return cborCOSEKey(x: x, y: y)
        }

        static func cborCOSEKey(x: [UInt8], y: [UInt8]) -> [UInt8] {
            // Per RFC 9052 / §5.10.5, the EC2 COSE key for ES256 is:
            //   {1: 2, 3: -7, -1: 1, -2: <x>, -3: <y>}
            // SwiftCBOR encodes a map with both positive and negative integer
            // keys; deterministic ordering isn't required — swift-webauthn
            // indexes by key rather than relying on order.
            let map: [CBOR: CBOR] = [
                .unsignedInt(1): .unsignedInt(2),          // kty = EC2
                .unsignedInt(3): .negativeInt(6),          // alg = -7 (ES256)
                .negativeInt(0): .unsignedInt(1),          // crv = P-256
                .negativeInt(1): .byteString(x),           // x coord
                .negativeInt(2): .byteString(y),           // y coord
            ]
            return CBOR.map(map).encode()
        }
    }

    /// Build a full registration payload signed by a freshly-generated P-256
    /// key. The `challenge` bytes will be echoed in `clientDataJSON` so the
    /// relying party can match the stored challenge.
    static func registration(challenge: [UInt8]) -> Registration {
        let privateKey = P256.Signing.PrivateKey()
        let credentialID: [UInt8] = [0x01, 0x02, 0x03, 0x04]
        let signCount: UInt32 = 0

        let cosePublicKey = Registration.cosePublicKey(for: privateKey)

        let authData = buildAuthData(
            rpID: rpID,
            flags: Flags.registration,
            counter: signCount,
            attestedCredentialData: (
                aaguid: [UInt8](repeating: 0, count: 16),
                credentialID: credentialID,
                cosePublicKey: cosePublicKey
            )
        )

        let attestationObject = cborAttestationObjectNone(authData: authData)

        let clientDataJSON = buildClientDataJSON(
            type: "webauthn.create",
            challenge: challenge,
            origin: rpOrigin
        )

        let body = buildRegistrationBody(
            credentialID: credentialID,
            clientDataJSON: clientDataJSON,
            attestationObject: attestationObject,
            transports: ["internal", "hybrid"]
        )

        return Registration(
            privateKey: privateKey,
            credentialID: credentialID,
            challenge: challenge,
            body: body,
            signCount: signCount
        )
    }

    /// Build an authentication payload signed by `privateKey` for a credential
    /// previously registered via `registration(challenge:)`.
    static func authentication(
        privateKey: P256.Signing.PrivateKey,
        credentialID: [UInt8],
        challenge: [UInt8],
        signCount: UInt32 = 1
    ) throws -> Data {
        let authData = buildAuthData(
            rpID: rpID,
            flags: Flags.authentication,
            counter: signCount,
            attestedCredentialData: nil
        )

        let clientDataJSON = buildClientDataJSON(
            type: "webauthn.get",
            challenge: challenge,
            origin: rpOrigin
        )

        // WebAuthn signature base is authData || SHA256(clientDataJSON).
        let clientDataHash = SHA256.hash(data: clientDataJSON)
        var signatureBase = Data(authData)
        signatureBase.append(Data(clientDataHash))

        let signature = try privateKey.signature(for: signatureBase)
        let derSignature = signature.derRepresentation

        return buildAuthenticationBody(
            credentialID: credentialID,
            clientDataJSON: clientDataJSON,
            authenticatorData: authData,
            signature: [UInt8](derSignature)
        )
    }

    // MARK: - AuthData layout

    /// Flag byte per §6.1 of the WebAuthn spec. Bit indices: UP=0, UV=2,
    /// BE=3, BS=4, AT=6, ED=7.
    struct Flags {
        static let registration: UInt8 = 0b0100_0101  // AT | UV | UP
        static let authentication: UInt8 = 0b0000_0101  // UV | UP
    }

    /// Build the binary `authData` structure. The layout is fixed-width
    /// through counter and variable after that, so we just concatenate.
    private static func buildAuthData(
        rpID: String,
        flags: UInt8,
        counter: UInt32,
        attestedCredentialData: (aaguid: [UInt8], credentialID: [UInt8], cosePublicKey: [UInt8])?
    ) -> [UInt8] {
        var bytes: [UInt8] = []

        // 32 bytes: SHA-256(RP ID)
        bytes.append(contentsOf: SHA256.hash(data: Data(rpID.utf8)))

        // 1 byte: flags
        bytes.append(flags)

        // 4 bytes: sign count (big-endian)
        bytes.append(UInt8((counter >> 24) & 0xFF))
        bytes.append(UInt8((counter >> 16) & 0xFF))
        bytes.append(UInt8((counter >> 8) & 0xFF))
        bytes.append(UInt8(counter & 0xFF))

        if let attested = attestedCredentialData {
            // 16 bytes: AAGUID
            bytes.append(contentsOf: attested.aaguid)
            // 2 bytes: credential ID length (big-endian)
            let idLen = UInt16(attested.credentialID.count)
            bytes.append(UInt8((idLen >> 8) & 0xFF))
            bytes.append(UInt8(idLen & 0xFF))
            // N bytes: credential ID
            bytes.append(contentsOf: attested.credentialID)
            // M bytes: COSE public key
            bytes.append(contentsOf: attested.cosePublicKey)
        }

        return bytes
    }

    // MARK: - CBOR encoders

    private static func cborAttestationObjectNone(authData: [UInt8]) -> [UInt8] {
        let map: [CBOR: CBOR] = [
            .utf8String("fmt"):      .utf8String("none"),
            .utf8String("attStmt"):  .map([:]),
            .utf8String("authData"): .byteString(authData),
        ]
        return CBOR.map(map).encode()
    }

    // MARK: - JSON builders

    private static func buildClientDataJSON(
        type: String,
        challenge: [UInt8],
        origin: String
    ) -> [UInt8] {
        // Serialize with JSONSerialization and sorted keys — swift-webauthn
        // doesn't require deterministic ordering, but sorting keeps the
        // fixture reproducible under debug.
        let object: [String: String] = [
            "type": type,
            "challenge": base64url(challenge),
            "origin": origin,
        ]
        let data = try! JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys]
        )
        return [UInt8](data)
    }

    private static func buildRegistrationBody(
        credentialID: [UInt8],
        clientDataJSON: [UInt8],
        attestationObject: [UInt8],
        transports: [String]
    ) -> Data {
        let object: [String: Any] = [
            "id": base64url(credentialID),
            "type": "public-key",
            "rawId": base64url(credentialID),
            "response": [
                "clientDataJSON": base64url(clientDataJSON),
                "attestationObject": base64url(attestationObject),
                "transports": transports,
            ],
        ]
        return try! JSONSerialization.data(withJSONObject: object)
    }

    private static func buildAuthenticationBody(
        credentialID: [UInt8],
        clientDataJSON: [UInt8],
        authenticatorData: [UInt8],
        signature: [UInt8]
    ) -> Data {
        let object: [String: Any] = [
            "id": base64url(credentialID),
            "type": "public-key",
            "rawId": base64url(credentialID),
            "response": [
                "clientDataJSON": base64url(clientDataJSON),
                "authenticatorData": base64url(authenticatorData),
                "signature": base64url(signature),
            ],
        ]
        return try! JSONSerialization.data(withJSONObject: object)
    }

    // MARK: - base64url

    static func base64url(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
