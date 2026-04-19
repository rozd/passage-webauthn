import Foundation
import Passage
import Vapor

// Minimal conformances for the handful of Passage protocols the passkey
// service touches: User, StoredPasskeyChallenge, StoredPasskeyCredential.
// They only carry the fields swift-webauthn needs to verify a ceremony;
// other fields return sensible defaults.

struct MockUser: User {
    typealias Id = UUID

    var id: UUID?
    var email: String? = nil
    var phone: String? = nil
    var username: String? = nil
    var passwordHash: String? = nil
    var isAnonymous: Bool = false
    var isEmailVerified: Bool = false
    var isPhoneVerified: Bool = false

    var sessionID: String { id?.uuidString ?? "" }
}

struct MockStoredPasskeyChallenge: StoredPasskeyChallenge {
    typealias Id = UUID
    typealias AssociatedUser = MockUser

    var id: UUID? = UUID()
    var user: MockUser? = nil
    var kind: PasskeyChallengeKind
    var challengeHash: String
    var expiresAt: Date
    var consumedAt: Date? = nil
    var createdAt: Date? = Date()
}

struct MockStoredPasskeyCredential: StoredPasskeyCredential {
    typealias Id = UUID
    typealias AssociatedUser = MockUser

    var id: UUID? = UUID()
    var user: MockUser
    var credentialID: String
    var publicKey: Data
    var signCount: UInt32
    var uvInitialized: Bool = true
    var transports: [AuthenticatorTransport] = []
    var backupEligible: Bool = false
    var isBackedUp: Bool = false
    var aaguid: String? = nil
    var attestationFormat: String? = nil
    var createdAt: Date? = Date()
    var updatedAt: Date? = Date()
}
