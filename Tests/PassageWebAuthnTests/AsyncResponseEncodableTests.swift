import Foundation
import Testing
import Vapor
import VaporTesting

// Selective WebAuthn imports to avoid top-level name collisions with
// Passage (see note in WebAuthnPasskeyServiceTests.swift).
import struct WebAuthn.PublicKeyCredentialCreationOptions
import struct WebAuthn.PublicKeyCredentialRequestOptions
import struct WebAuthn.PublicKeyCredentialParameters

@testable import PassageWebAuthn

// Exercises the two retroactive `AsyncResponseEncodable` conformances that
// let swift-webauthn's native option types flow through Passage's route
// handlers as Vapor response bodies without a DTO intermediary.

@Suite("AsyncResponseEncodable conformance", .serialized)
struct AsyncResponseEncodableTests {

    @Test("PublicKeyCredentialCreationOptions encodes as JSON and round-trips")
    func creationOptionsEncode() async throws {
        try await withApp { app in
            let request = Request(application: app, on: app.eventLoopGroup.any())
            let options = WebAuthn.PublicKeyCredentialCreationOptions(
                challenge: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10],
                user: .init(id: [0xAA], name: "alice", displayName: "Alice"),
                relyingParty: .init(id: "example.com", name: "Example"),
                publicKeyCredentialParameters: [.init(alg: .algES256)],
                timeout: .seconds(60),
                attestation: .none
            )

            let response = try await options.encodeResponse(for: request)

            #expect(response.status == .ok)
            #expect(response.headers.contentType == .json)

            let bytes = try #require(response.body.buffer)
                .getBytes(at: 0, length: response.body.buffer?.readableBytes ?? 0)
            let data = Data(bytes ?? [])
            let decoded = try JSONDecoder().decode(
                WebAuthn.PublicKeyCredentialCreationOptions.self,
                from: data
            )
            #expect(decoded.challenge == options.challenge)
            #expect(decoded.relyingParty.id == "example.com")
            #expect(decoded.user.name == "alice")
        }
    }

    @Test("PublicKeyCredentialRequestOptions encodes as JSON and round-trips")
    func requestOptionsEncode() async throws {
        try await withApp { app in
            let request = Request(application: app, on: app.eventLoopGroup.any())
            let options = WebAuthn.PublicKeyCredentialRequestOptions(
                challenge: Array(repeating: 0xAA, count: 16),
                timeout: .seconds(60),
                relyingPartyID: "example.com",
                allowCredentials: [
                    .init(id: [0x01, 0x02, 0x03], transports: [.internal])
                ],
                userVerification: .preferred
            )

            let response = try await options.encodeResponse(for: request)

            #expect(response.status == .ok)
            #expect(response.headers.contentType == .json)

            let bytes = try #require(response.body.buffer)
                .getBytes(at: 0, length: response.body.buffer?.readableBytes ?? 0)
            let data = Data(bytes ?? [])
            let decoded = try JSONDecoder().decode(
                WebAuthn.PublicKeyCredentialRequestOptions.self,
                from: data
            )
            #expect(decoded.challenge == options.challenge)
            #expect(decoded.relyingPartyID == "example.com")
            #expect(decoded.userVerification?.rawValue == "preferred")
            #expect(decoded.allowCredentials?.first?.id == [0x01, 0x02, 0x03])
        }
    }
}

// MARK: - App harness

private func withApp(_ work: (Application) async throws -> Void) async throws {
    let app = try await Application.make(.testing)
    do {
        try await work(app)
    } catch {
        try? await app.asyncShutdown()
        throw error
    }
    try await app.asyncShutdown()
}
