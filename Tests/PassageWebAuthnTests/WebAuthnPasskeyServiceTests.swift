import Foundation
import Testing
import Passage
import Vapor

// Passage and WebAuthn both export top-level types named
// UserVerificationRequirement, AttestationConveyancePreference,
// COSEAlgorithmIdentifier, PublicKeyCredentialUserEntity, etc. Use
// selective WebAuthn imports so unqualified names bind to Passage.
import struct WebAuthn.WebAuthnManager
import struct WebAuthn.PublicKeyCredentialCreationOptions
import struct WebAuthn.PublicKeyCredentialRequestOptions

@testable import PassageWebAuthn

// MARK: - Fixtures

private enum Fixtures {
    static let rpID = "login.example.com"
    static let rpName = "Example"
    static let rpOrigin = "https://login.example.com"

    static func service() -> WebAuthnPasskeyService {
        WebAuthnPasskeyService(
            configuration: WebAuthnManager.Configuration(
                relyingPartyID: rpID,
                relyingPartyName: rpName,
                relyingPartyOrigin: rpOrigin
            )
        )
    }

    static func user(
        id: Data = Data([0xAA, 0xBB, 0xCC, 0xDD]),
        name: String = "alice@example.com",
        displayName: String = "Alice"
    ) -> PublicKeyCredentialUserEntity {
        .init(name: name, id: id, displayName: displayName)
    }

    static func policy(
        timeout: Duration? = .seconds(60),
        attestation: AttestationConveyancePreference = .none,
        userVerification: UserVerificationRequirement = .preferred,
        supportedAlgorithms: [COSEAlgorithmIdentifier] = [.ES256, .RS256],
        allowDiscoverableLogin: Bool = true
    ) -> Passage.Configuration.Passkey.Policy {
        .init(
            timeout: timeout,
            attestation: attestation,
            userVerification: userVerification,
            supportedAlgorithms: supportedAlgorithms,
            allowDiscoverableLogin: allowDiscoverableLogin
        )
    }

    /// Base64url-encode bytes in the shape swift-webauthn emits (no padding,
    /// URL-safe alphabet). Used to build synthetic request bodies.
    static func base64url(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Build a registration body whose clientDataJSON carries the given
    /// challenge bytes. Enough to reach the lookupChallenge closure; the
    /// attestationObject is garbage because we error out before parsing it.
    static func registrationBody(challenge: [UInt8], credentialID: [UInt8] = [0x01, 0x02, 0x03]) -> Data {
        let clientData: [String: String] = [
            "type": "webauthn.create",
            "challenge": base64url(challenge),
            "origin": rpOrigin
        ]
        let clientDataJSON = try! JSONSerialization.data(withJSONObject: clientData)
        let body: [String: Any] = [
            "id": base64url(credentialID),
            "type": "public-key",
            "rawId": base64url(credentialID),
            "response": [
                "clientDataJSON": base64url([UInt8](clientDataJSON)),
                "attestationObject": base64url([0xDE, 0xAD, 0xBE, 0xEF]),
            ],
        ]
        return try! JSONSerialization.data(withJSONObject: body)
    }

    /// Build an authentication body mirroring the registration helper.
    static func authenticationBody(challenge: [UInt8], credentialID: [UInt8] = [0x01, 0x02, 0x03]) -> Data {
        let clientData: [String: String] = [
            "type": "webauthn.get",
            "challenge": base64url(challenge),
            "origin": rpOrigin
        ]
        let clientDataJSON = try! JSONSerialization.data(withJSONObject: clientData)
        let body: [String: Any] = [
            "id": base64url(credentialID),
            "type": "public-key",
            "rawId": base64url(credentialID),
            "response": [
                "clientDataJSON": base64url([UInt8](clientDataJSON)),
                "authenticatorData": base64url([0xDE, 0xAD, 0xBE, 0xEF]),
                "signature": base64url([0x00, 0x01]),
            ],
        ]
        return try! JSONSerialization.data(withJSONObject: body)
    }
}

// MARK: - beginRegistration

@Suite("beginRegistration")
struct BeginRegistrationTests {

    @Test("emits challenge matching options.challenge and kind == .registration")
    func challengePassthrough() async throws {
        let service = Fixtures.service()
        let user = Fixtures.user()

        let result = try await service.beginRegistration(
            with: user,
            policy: Fixtures.policy(),
            challengeTTL: 300
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialCreationOptions)
        #expect(result.challenge.bytes == Data(options.challenge))
        #expect(result.challenge.kind == .registration)
    }

    @Test("challenge.expiresAt is approximately now + TTL")
    func challengeExpiration() async throws {
        let service = Fixtures.service()
        let ttl: TimeInterval = 600
        let before = Date()

        let result = try await service.beginRegistration(
            with: Fixtures.user(),
            policy: Fixtures.policy(),
            challengeTTL: ttl
        )

        let expected = before.addingTimeInterval(ttl)
        let drift = abs(result.challenge.expiresAt.timeIntervalSince(expected))
        #expect(drift < 1.0, "expected expiresAt within 1s of now+TTL, got drift=\(drift)s")
    }

    @Test("user entity fields are forwarded verbatim")
    func userPassthrough() async throws {
        let service = Fixtures.service()
        let userID = Data([0x11, 0x22, 0x33, 0x44, 0x55])
        let user = Fixtures.user(id: userID, name: "bob@example.com", displayName: "Bob")

        let result = try await service.beginRegistration(
            with: user,
            policy: Fixtures.policy(),
            challengeTTL: 300
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialCreationOptions)
        #expect(options.user.id == [UInt8](userID))
        #expect(options.user.name == "bob@example.com")
        #expect(options.user.displayName == "Bob")
    }

    @Test("relying party configuration propagates to options")
    func relyingPartyPassthrough() async throws {
        let service = Fixtures.service()
        let result = try await service.beginRegistration(
            with: Fixtures.user(),
            policy: Fixtures.policy(),
            challengeTTL: 300
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialCreationOptions)
        #expect(options.relyingParty.id == Fixtures.rpID)
        #expect(options.relyingParty.name == Fixtures.rpName)
    }

    @Test("supported algorithms round-trip matching Passage's raw values")
    func algorithmPassthrough() async throws {
        let service = Fixtures.service()
        let policy = Fixtures.policy(supportedAlgorithms: [.ES256, .RS256, .PS256])

        let result = try await service.beginRegistration(
            with: Fixtures.user(),
            policy: policy,
            challengeTTL: 300
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialCreationOptions)
        let algs = options.publicKeyCredentialParameters.map(\.alg.rawValue)
        #expect(algs == [-7, -257, -37])
    }

    @Test("Passage-only algorithms (EdDSA/ESP*) are silently dropped")
    func unsupportedAlgorithmsAreDropped() async throws {
        let service = Fixtures.service()
        // EdDSA (-8), ESP256 (-9), ESP384 (-51), ESP512 (-52) are not in
        // swift-webauthn's COSEAlgorithmIdentifier and must be filtered out
        // rather than crashing.
        let policy = Fixtures.policy(
            supportedAlgorithms: [.EdDSA, .ESP256, .ESP384, .ESP512, .ES256]
        )

        let result = try await service.beginRegistration(
            with: Fixtures.user(),
            policy: policy,
            challengeTTL: 300
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialCreationOptions)
        let algs = options.publicKeyCredentialParameters.map(\.alg.rawValue)
        #expect(algs == [-7])
    }

    @Test("attestation preference forwarded by raw value")
    func attestationPassthrough() async throws {
        let service = Fixtures.service()
        let policy = Fixtures.policy(attestation: .direct)

        let result = try await service.beginRegistration(
            with: Fixtures.user(),
            policy: policy,
            challengeTTL: 300
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialCreationOptions)
        #expect(options.attestation.rawValue == "direct")
    }

    @Test("timeout forwarded when policy supplies one")
    func timeoutPassthrough() async throws {
        let service = Fixtures.service()
        let policy = Fixtures.policy(timeout: .seconds(45))

        let result = try await service.beginRegistration(
            with: Fixtures.user(),
            policy: policy,
            challengeTTL: 300
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialCreationOptions)
        #expect(options.timeout == .seconds(45))
    }
}

// MARK: - beginAuthentication

@Suite("beginAuthentication")
struct BeginAuthenticationTests {

    @Test("discoverable ceremony omits allowCredentials")
    func discoverable() async throws {
        let service = Fixtures.service()
        let result = try await service.beginAuthentication(
            allowCredentials: nil,
            policy: Fixtures.policy(),
            challengeTTL: 120
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialRequestOptions)
        #expect(options.allowCredentials == nil)
        #expect(result.challenge.kind == .authentication)
        #expect(result.challenge.bytes == Data(options.challenge))
    }

    @Test("hinted ceremony decodes base64url credential IDs into raw bytes")
    func hintedDescriptorsAreDecoded() async throws {
        let service = Fixtures.service()
        let rawID: [UInt8] = [0x10, 0x20, 0x30, 0x40]
        let descriptor = PasskeyCredentialDescriptor(
            credentialID: Fixtures.base64url(rawID),
            transports: [.internal, .hybrid]
        )

        let result = try await service.beginAuthentication(
            allowCredentials: [descriptor],
            policy: Fixtures.policy(),
            challengeTTL: 120
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialRequestOptions)
        let allowed = try #require(options.allowCredentials)
        #expect(allowed.count == 1)
        #expect(allowed[0].id == rawID)
        let transportValues = allowed[0].transports.map(\.rawValue).sorted()
        #expect(transportValues == ["hybrid", "internal"])
    }

    @Test("unknown transport strings round-trip through unreferenced enum")
    func unknownTransportRoundTrip() async throws {
        let service = Fixtures.service()
        let rawID: [UInt8] = [0xA1, 0xB2]
        let descriptor = PasskeyCredentialDescriptor(
            credentialID: Fixtures.base64url(rawID),
            transports: [.unknown("smart-card")]
        )

        let result = try await service.beginAuthentication(
            allowCredentials: [descriptor],
            policy: Fixtures.policy(),
            challengeTTL: 120
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialRequestOptions)
        let allowed = try #require(options.allowCredentials)
        #expect(allowed[0].transports.map(\.rawValue) == ["smart-card"])
    }

    @Test("userVerification preference forwarded by raw value", arguments: [
        (UserVerificationRequirement.required, "required"),
        (.preferred, "preferred"),
        (.discouraged, "discouraged"),
    ])
    func userVerificationPassthrough(
        passage: UserVerificationRequirement,
        expected: String
    ) async throws {
        let service = Fixtures.service()
        let result = try await service.beginAuthentication(
            allowCredentials: nil,
            policy: Fixtures.policy(userVerification: passage),
            challengeTTL: 120
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialRequestOptions)
        #expect(options.userVerification?.rawValue == expected)
    }

    @Test("relyingPartyID propagates from manager configuration")
    func relyingPartyIDPassthrough() async throws {
        let service = Fixtures.service()
        let result = try await service.beginAuthentication(
            allowCredentials: nil,
            policy: Fixtures.policy(),
            challengeTTL: 120
        )

        let options = try #require(result.body as? WebAuthn.PublicKeyCredentialRequestOptions)
        #expect(options.relyingPartyID == Fixtures.rpID)
    }

    @Test("challenge.expiresAt respects TTL")
    func challengeExpiration() async throws {
        let service = Fixtures.service()
        let ttl: TimeInterval = 90
        let before = Date()

        let result = try await service.beginAuthentication(
            allowCredentials: nil,
            policy: Fixtures.policy(),
            challengeTTL: ttl
        )

        let drift = abs(result.challenge.expiresAt.timeIntervalSince(before.addingTimeInterval(ttl)))
        #expect(drift < 1.0)
    }
}

// MARK: - finishRegistration error paths

/// Test-only container for observing values mutated inside @Sendable
/// closures. Safe here because tests are serialized within a test function
/// and no real concurrency crosses the boundary.
private final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

@Suite("finishRegistration error paths")
struct FinishRegistrationTests {

    @Test("empty body throws a decoding error")
    func emptyBody() async throws {
        let service = Fixtures.service()
        await #expect(throws: DecodingError.self) {
            _ = try await service.finishRegistration(
                rawBody: Data(),
                policy: Fixtures.policy(),
                lookupChallenge: { _ in nil },
                confirmUnused: { _ in true }
            )
        }
    }

    @Test("malformed JSON throws a decoding error")
    func malformedJSON() async throws {
        let service = Fixtures.service()
        let body = Data("{ this is not valid json".utf8)
        await #expect(throws: DecodingError.self) {
            _ = try await service.finishRegistration(
                rawBody: body,
                policy: Fixtures.policy(),
                lookupChallenge: { _ in nil },
                confirmUnused: { _ in true }
            )
        }
    }

    @Test("valid body but unknown challenge throws .invalidPasskeyChallenge")
    func unknownChallenge() async throws {
        let service = Fixtures.service()
        let challenge: [UInt8] = [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF]
        let body = Fixtures.registrationBody(challenge: challenge)

        let seen = Box<Data?>(nil)
        do {
            _ = try await service.finishRegistration(
                rawBody: body,
                policy: Fixtures.policy(),
                lookupChallenge: { bytes in
                    seen.value = bytes
                    return nil
                },
                confirmUnused: { _ in true }
            )
            Issue.record("expected to throw")
        } catch let error as AuthenticationError {
            guard case .invalidPasskeyChallenge = error else {
                Issue.record("wrong case: \(error)")
                return
            }
            #expect(seen.value == Data(challenge), "lookupChallenge received different bytes than clientDataJSON carried")
        } catch {
            Issue.record("unexpected error type: \(error)")
        }
    }
}

// MARK: - finishAuthentication error paths

@Suite("finishAuthentication error paths")
struct FinishAuthenticationTests {

    @Test("empty body throws a decoding error")
    func emptyBody() async throws {
        let service = Fixtures.service()
        await #expect(throws: DecodingError.self) {
            _ = try await service.finishAuthentication(
                rawBody: Data(),
                policy: Fixtures.policy(),
                lookupChallenge: { _ in nil },
                lookupCredential: { _ in nil }
            )
        }
    }

    @Test("valid body but unknown challenge throws .invalidPasskeyChallenge")
    func unknownChallenge() async throws {
        let service = Fixtures.service()
        let challenge: [UInt8] = Array(repeating: 0xAB, count: 16)
        let body = Fixtures.authenticationBody(challenge: challenge)

        let seen = Box<Data?>(nil)
        do {
            _ = try await service.finishAuthentication(
                rawBody: body,
                policy: Fixtures.policy(),
                lookupChallenge: { bytes in
                    seen.value = bytes
                    return nil
                },
                lookupCredential: { _ in nil }
            )
            Issue.record("expected to throw")
        } catch let error as AuthenticationError {
            guard case .invalidPasskeyChallenge = error else {
                Issue.record("wrong case: \(error)")
                return
            }
            #expect(seen.value == Data(challenge))
        } catch {
            Issue.record("unexpected error type: \(error)")
        }
    }
}
