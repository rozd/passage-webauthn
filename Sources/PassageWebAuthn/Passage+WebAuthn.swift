import Foundation
import Passage
import Vapor
import WebAuthn

// MARK: - Response pass-through
//
// swift-webauthn's PublicKeyCredentialCreationOptions is Codable + Sendable;
// this single retroactive conformance turns it into a valid Vapor response
// body so `WebAuthnPasskeyService.beginRegistration` can return it directly
// via `PasskeyBeginResult.body`. Passage core never names or inspects the
// type — it only sees `any AsyncResponseEncodable & Sendable`.

extension WebAuthn.PublicKeyCredentialCreationOptions: @retroactive AsyncResponseEncodable {
    public func encodeResponse(for request: Request) async throws -> Response {
        let data = try JSONEncoder().encode(self)
        var headers = HTTPHeaders()
        headers.contentType = .json
        return Response(status: .ok, headers: headers, body: .init(data: data))
    }
}

extension WebAuthn.PublicKeyCredentialRequestOptions: @retroactive AsyncResponseEncodable {
    public func encodeResponse(for request: Request) async throws -> Response {
        let data = try JSONEncoder().encode(self)
        var headers = HTTPHeaders()
        headers.contentType = .json
        return Response(status: .ok, headers: headers, body: .init(data: data))
    }
}

// MARK: - Output-side mapping (swift-webauthn result → Passage storage DTO)
//
// AAGUID / attestationFormat / UV flag are not reachable via swift-webauthn's
// public surface (AttestationObject's members are internal). Derive UV from
// policy; leave AAGUID and format nil.

extension PasskeyCredential {
    init(
        with credential: WebAuthn.Credential,
        uvInitialized: Bool,
        transports: [AuthenticatorTransport]
    ) {
        self.init(
            credentialID:      credential.id,
            publicKey:         Data(credential.publicKey),
            signCount:         credential.signCount,
            uvInitialized:     uvInitialized,
            transports:        transports,
            backupEligible:    credential.backupEligible,
            isBackedUp:        credential.isBackedUp,
            aaguid:            nil,
            attestationFormat: nil
        )
    }
}
