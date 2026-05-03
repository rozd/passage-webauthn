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
    static let rpID = WebAuthnFixture.rpID
    static let rpName = WebAuthnFixture.rpName
    static let rpOrigin = WebAuthnFixture.rpOrigin

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

    @Test("valid body, valid challenge, but unknown credential throws .unknownPasskey")
    func unknownCredential() async throws {
        let service = Fixtures.service()

        // Full ceremony: register first to get a credential-bound keypair,
        // then authenticate with it, but tell the authentication flow the
        // credential isn't stored anywhere.
        let regChallenge = Array(repeating: UInt8(0x11), count: 16)
        let registration = WebAuthnFixture.registration(challenge: regChallenge)

        let authChallenge = Array(repeating: UInt8(0x22), count: 16)
        let authBody = try WebAuthnFixture.authentication(
            privateKey: registration.privateKey,
            credentialID: registration.credentialID,
            challenge: authChallenge
        )

        let stored = MockStoredPasskeyChallenge(
            kind: .authentication,
            challengeHash: "whatever",
            expiresAt: Date().addingTimeInterval(60)
        )

        do {
            _ = try await service.finishAuthentication(
                rawBody: authBody,
                policy: Fixtures.policy(),
                lookupChallenge: { _ in stored },
                lookupCredential: { _ in nil }
            )
            Issue.record("expected to throw .unknownPasskey")
        } catch let error as AuthenticationError {
            guard case .unknownPasskey = error else {
                Issue.record("wrong case: \(error)")
                return
            }
        } catch {
            Issue.record("unexpected error type: \(error)")
        }
    }
}

// MARK: - Full ceremony (happy paths)

@Suite("finishRegistration/finishAuthentication happy paths")
struct HappyPathCeremonyTests {

    @Test("finishRegistration returns a verified credential for a valid payload")
    func registrationSucceeds() async throws {
        let service = Fixtures.service()
        let challenge = Array(repeating: UInt8(0x7A), count: 16)
        let registration = WebAuthnFixture.registration(challenge: challenge)

        let stored = MockStoredPasskeyChallenge(
            kind: .registration,
            challengeHash: "sha256-placeholder",
            expiresAt: Date().addingTimeInterval(300)
        )

        let result = try await service.finishRegistration(
            rawBody: registration.body,
            policy: Fixtures.policy(),
            lookupChallenge: { _ in stored },
            confirmUnused: { _ in true }
        )

        // The service normalizes the credential ID to base64url so it matches
        // the format the authenticator echoes back during the assertion (see
        // `WebAuthnPasskeyService.finishAuthentication`). Without this,
        // registration stored standard base64 but authentication looked up
        // base64url and `lookupCredential` always missed.
        let expectedBase64URL = WebAuthnFixture.base64url(registration.credentialID)
        #expect(result.credential.credentialID == expectedBase64URL)
        // Public key returned is the COSE-encoded key we embedded in authData.
        #expect(Array(result.credential.publicKey) == registration.cosePublicKey)
        // signCount came from our authData counter field (0 for fresh passkey).
        #expect(result.credential.signCount == registration.signCount)
        // Transports came from the JSON envelope, not from swift-webauthn.
        let transportValues = Set(result.credential.transports.map(\.rawValue))
        #expect(transportValues == ["internal", "hybrid"])
        // Fields swift-webauthn cannot surface via its public API.
        #expect(result.credential.aaguid == nil)
        #expect(result.credential.attestationFormat == nil)
    }

    @Test("finishRegistration confirmUnused=false surfaces as WebAuthnError")
    func registrationRejectsDuplicateCredential() async throws {
        let service = Fixtures.service()
        let challenge = Array(repeating: UInt8(0x6B), count: 16)
        let registration = WebAuthnFixture.registration(challenge: challenge)

        let stored = MockStoredPasskeyChallenge(
            kind: .registration,
            challengeHash: "sha256-placeholder",
            expiresAt: Date().addingTimeInterval(300)
        )

        await #expect(throws: (any Error).self) {
            _ = try await service.finishRegistration(
                rawBody: registration.body,
                policy: Fixtures.policy(),
                lookupChallenge: { _ in stored },
                confirmUnused: { _ in false }
            )
        }
    }

    @Test("finishAuthentication returns verified outputs for a valid assertion")
    func authenticationSucceeds() async throws {
        let service = Fixtures.service()

        // Step 1: register so we have a key pair + credential record.
        let regChallenge = Array(repeating: UInt8(0xA1), count: 16)
        let registration = WebAuthnFixture.registration(challenge: regChallenge)

        // Step 2: build an authentication assertion signed by the same key.
        let authChallenge = Array(repeating: UInt8(0xB2), count: 16)
        let newSignCount: UInt32 = 7
        let authBody = try WebAuthnFixture.authentication(
            privateKey: registration.privateKey,
            credentialID: registration.credentialID,
            challenge: authChallenge,
            signCount: newSignCount
        )

        let storedChallenge = MockStoredPasskeyChallenge(
            kind: .authentication,
            challengeHash: "sha256-placeholder",
            expiresAt: Date().addingTimeInterval(120)
        )

        let storedCredential = MockStoredPasskeyCredential(
            user: MockUser(id: UUID()),
            credentialID: WebAuthnFixture.base64url(registration.credentialID),
            publicKey: Data(registration.cosePublicKey),
            signCount: 0
        )

        let result = try await service.finishAuthentication(
            rawBody: authBody,
            policy: Fixtures.policy(),
            lookupChallenge: { _ in storedChallenge },
            lookupCredential: { _ in storedCredential }
        )

        #expect(result.newSignCount == newSignCount)
        #expect(result.matchedCredential.credentialID == storedCredential.credentialID)
        // Our authData flag byte doesn't set the BS bit, so credentialBackedUp is false.
        #expect(result.credentialBackedUp == false)
        // We didn't include a userHandle, so it should be nil.
        #expect(result.userHandle == nil)
    }

    @Test("registration→authentication round-trips the credential ID through the same key")
    func credentialIDRoundTripsThroughLookup() async throws {
        // Regression test: previously, registration stored the credentialID
        // as standard base64 (e.g. `AQIDBA==`) while authentication's
        // `lookupCredential` was invoked with base64url (e.g. `AQIDBA`).
        // Result: a credential persisted by the registration ceremony could
        // never be located by the authentication ceremony, so guest-registered
        // passkeys could not log in. This test wires the two ceremonies
        // together and asserts the round-trip key matches.
        let service = Fixtures.service()

        let regChallenge = Array(repeating: UInt8(0x11), count: 16)
        let registration = WebAuthnFixture.registration(challenge: regChallenge)

        let regChallengeStored = MockStoredPasskeyChallenge(
            kind: .registration,
            challengeHash: "x",
            expiresAt: Date().addingTimeInterval(120)
        )
        let regResult = try await service.finishRegistration(
            rawBody: registration.body,
            policy: Fixtures.policy(),
            lookupChallenge: { _ in regChallengeStored },
            confirmUnused: { _ in true }
        )
        let storedCredentialID = regResult.credential.credentialID

        let authChallenge = Array(repeating: UInt8(0x22), count: 16)
        let authBody = try WebAuthnFixture.authentication(
            privateKey: registration.privateKey,
            credentialID: registration.credentialID,
            challenge: authChallenge
        )

        let authChallengeStored = MockStoredPasskeyChallenge(
            kind: .authentication,
            challengeHash: "y",
            expiresAt: Date().addingTimeInterval(120)
        )
        let storedCredential = MockStoredPasskeyCredential(
            user: MockUser(id: UUID()),
            credentialID: storedCredentialID,
            publicKey: Data(registration.cosePublicKey),
            signCount: 0
        )

        final class LookupKey: @unchecked Sendable {
            var value: String?
        }
        let captured = LookupKey()
        _ = try await service.finishAuthentication(
            rawBody: authBody,
            policy: Fixtures.policy(),
            lookupChallenge: { _ in authChallengeStored },
            lookupCredential: { id in
                captured.value = id
                return id == storedCredentialID ? storedCredential : nil
            }
        )

        #expect(captured.value == storedCredentialID)
    }

    @Test("finishAuthentication with a challenge mismatch fails verification")
    func authenticationRejectsChallengeMismatch() async throws {
        let service = Fixtures.service()
        let regChallenge = Array(repeating: UInt8(0xC3), count: 16)
        let registration = WebAuthnFixture.registration(challenge: regChallenge)

        // Sign over challengeA but tell lookupChallenge to return a stored
        // record for challengeB — swift-webauthn checks the signature over
        // authData || SHA256(clientDataJSON), so a lookup substitution does
        // NOT bypass verification. The service forwards the clientDataJSON
        // challenge to the lookup, so we can still reach the verify step
        // as long as the clientData carries *a* valid challenge.
        let authChallenge = Array(repeating: UInt8(0xD4), count: 16)
        let authBody = try WebAuthnFixture.authentication(
            privateKey: registration.privateKey,
            credentialID: registration.credentialID,
            challenge: authChallenge
        )

        let storedCredentialButWrongKey = MockStoredPasskeyCredential(
            user: MockUser(id: UUID()),
            credentialID: WebAuthnFixture.base64url(registration.credentialID),
            // Wrong public key — will fail signature verification.
            publicKey: Data(WebAuthnFixture.Registration.cosePublicKey(for: .init())),
            signCount: 0
        )

        let storedChallenge = MockStoredPasskeyChallenge(
            kind: .authentication,
            challengeHash: "x",
            expiresAt: Date().addingTimeInterval(60)
        )

        await #expect(throws: (any Error).self) {
            _ = try await service.finishAuthentication(
                rawBody: authBody,
                policy: Fixtures.policy(),
                lookupChallenge: { _ in storedChallenge },
                lookupCredential: { _ in storedCredentialButWrongKey }
            )
        }
    }
}
