import Foundation
import Passage
import Vapor
import WebAuthn

public struct WebAuthnPasskeyService: Passage.PasskeyService {
    private let manager: WebAuthnManager

    public init(configuration: WebAuthnManager.Configuration) {
        self.manager = WebAuthnManager(configuration: configuration)
    }

    public func beginRegistration(
        with user: Passage::PublicKeyCredentialUserEntity,
        policy: Passage.Configuration.Passkey.Policy,
        challengeTTL: TimeInterval
    ) async throws -> PasskeyBeginResult {
        let options = manager.beginRegistration(
            user: WebAuthn.PublicKeyCredentialUserEntity(
                id: [UInt8](user.id),
                name: user.name,
                displayName: user.displayName
            ),
            timeout: policy.timeout,
            attestation: WebAuthn.AttestationConveyancePreference(rawValue: policy.attestation.rawValue),
            publicKeyCredentialParameters: Self.supportedParameters(from: policy)
        )
        let challenge = PasskeyChallenge(
            bytes: Data(options.challenge),
            kind: .registration,
            expiresAt: Date().addingTimeInterval(challengeTTL)
        )
        return PasskeyBeginResult(challenge: challenge, body: options)
    }

    public func finishRegistration(
        rawBody: Data,
        policy: Passage.Configuration.Passkey.Policy,
        lookupChallenge: @Sendable (_ challengeBytes: Data) async throws -> (any StoredPasskeyChallenge)?,
        confirmUnused: @Sendable (_ credentialID: String) async throws -> Bool
    ) async throws -> PasskeyFinishRegistrationResult {
        // Decode posted JSON directly into swift-webauthn's type — no Passage
        // DTO intermediary, no JSON round-trip.
        let registrationCredential = try JSONDecoder().decode(
            WebAuthn.RegistrationCredential.self,
            from: rawBody
        )

        // Extract the challenge bytes the browser echoed in clientDataJSON so
        // core can resolve the matching stored challenge. swift-webauthn will
        // verify the same bytes again via CollectedClientData.verify when we
        // call finishRegistration below.
        let clientDataJSON = Data(registrationCredential.attestationResponse.clientDataJSON)
        let clientData = try JSONDecoder().decode(WebAuthn.CollectedClientData.self, from: clientDataJSON)
        guard let challengeBytes = clientData.challenge.decodedBytes else {
            throw AuthenticationError.invalidPasskeyChallenge
        }

        guard let storedChallenge = try await lookupChallenge(Data(challengeBytes)) else {
            throw AuthenticationError.invalidPasskeyChallenge
        }

        // Re-parse the posted JSON for transports, which swift-webauthn does
        // not surface via AuthenticatorAttestationResponse. Small local scaffold
        // confined to this file — nothing escapes the module boundary.
        let transports = Self.decodeTransports(from: rawBody)

        let verified = try await manager.finishRegistration(
            challenge: challengeBytes,
            credentialCreationData: registrationCredential,
            requireUserVerification: policy.userVerification == .required,
            supportedPublicKeyAlgorithms: Self.supportedParameters(from: policy),
            confirmCredentialIDNotRegisteredYet: confirmUnused
        )

        let credential = PasskeyCredential(
            with: verified,
            uvInitialized: policy.userVerification == .required,
            transports: transports
        )
        return PasskeyFinishRegistrationResult(
            credential: credential,
            matchedChallenge: storedChallenge
        )
    }

    public func beginAuthentication(
        allowCredentials: [PasskeyCredentialDescriptor]?,
        policy: Passage.Configuration.Passkey.Policy,
        challengeTTL: TimeInterval
    ) async throws -> PasskeyBeginResult {
        let options = manager.beginAuthentication(
            timeout: policy.timeout,
            allowCredentials: allowCredentials?.map(Self.libraryDescriptor(from:)),
            userVerification: WebAuthn.UserVerificationRequirement(
                rawValue: policy.userVerification.rawValue
            )
        )
        let challenge = PasskeyChallenge(
            bytes: Data(options.challenge),
            kind: .authentication,
            expiresAt: Date().addingTimeInterval(challengeTTL)
        )
        return PasskeyBeginResult(challenge: challenge, body: options)
    }

    public func finishAuthentication(
        rawBody: Data,
        policy: Passage.Configuration.Passkey.Policy,
        lookupChallenge: @Sendable (_ challengeBytes: Data) async throws -> (any StoredPasskeyChallenge)?,
        lookupCredential: @Sendable (_ credentialID: String) async throws -> (any StoredPasskeyCredential)?
    ) async throws -> PasskeyFinishAuthenticationResult {
        let authenticationCredential = try JSONDecoder().decode(
            WebAuthn.AuthenticationCredential.self,
            from: rawBody
        )

        let clientDataJSON = Data(authenticationCredential.response.clientDataJSON)
        let clientData = try JSONDecoder().decode(WebAuthn.CollectedClientData.self, from: clientDataJSON)
        guard let challengeBytes = clientData.challenge.decodedBytes else {
            throw AuthenticationError.invalidPasskeyChallenge
        }

        guard let storedChallenge = try await lookupChallenge(Data(challengeBytes)) else {
            throw AuthenticationError.invalidPasskeyChallenge
        }

        guard let storedCredential = try await lookupCredential(authenticationCredential.id.asString()) else {
            throw AuthenticationError.unknownPasskey
        }

        let verified = try manager.finishAuthentication(
            credential: authenticationCredential,
            expectedChallenge: challengeBytes,
            credentialPublicKey: [UInt8](storedCredential.publicKey),
            credentialCurrentSignCount: storedCredential.signCount,
            requireUserVerification: policy.userVerification == .required
        )

        return PasskeyFinishAuthenticationResult(
            matchedCredential: storedCredential,
            matchedChallenge: storedChallenge,
            newSignCount: verified.newSignCount,
            credentialBackedUp: verified.credentialBackedUp,
            userHandle: authenticationCredential.response.userHandle.map { Data($0) }
        )
    }

    // MARK: - Helpers

    /// Both `Passage.COSEAlgorithmIdentifier` and
    /// `WebAuthn.COSEAlgorithmIdentifier` are `Int`-raw-value enums that share
    /// COSE identifiers verbatim (−7 for ES256, −257 for RS256, …), so we
    /// round-trip through `rawValue` instead of maintaining a case map.
    /// Unsupported values on the WebAuthn side are silently dropped.
    private static func supportedParameters(
        from policy: Passage.Configuration.Passkey.Policy
    ) -> [WebAuthn.PublicKeyCredentialParameters] {
        policy.supportedAlgorithms.compactMap { passageAlg in
            WebAuthn.COSEAlgorithmIdentifier(rawValue: passageAlg.rawValue).map {
                WebAuthn.PublicKeyCredentialParameters(type: .publicKey, alg: $0)
            }
        }
    }

    /// Map a Passage ``PasskeyCredentialDescriptor`` to the swift-webauthn
    /// ``PublicKeyCredentialDescriptor``. The credential ID is base64url —
    /// decode to raw bytes; unrecognised transport values round-trip through
    /// the library's unreferenced-string enum without loss.
    private static func libraryDescriptor(
        from descriptor: PasskeyCredentialDescriptor
    ) -> WebAuthn.PublicKeyCredentialDescriptor {
        let idBytes = WebAuthn.URLEncodedBase64(descriptor.credentialID).decodedBytes ?? []
        return WebAuthn.PublicKeyCredentialDescriptor(
            id: idBytes,
            transports: descriptor.transports.map {
                WebAuthn.PublicKeyCredentialDescriptor.AuthenticatorTransport(rawValue: $0.rawValue)
            }
        )
    }

    private struct TransportsEnvelope: Decodable {
        struct Response: Decodable {
            let transports: [String]?
        }
        let response: Response
    }

    private static func decodeTransports(from rawBody: Data) -> [AuthenticatorTransport] {
        guard let envelope = try? JSONDecoder().decode(TransportsEnvelope.self, from: rawBody) else {
            return []
        }
        return envelope.response.transports?.map { AuthenticatorTransport(rawValue: $0) } ?? []
    }
}
