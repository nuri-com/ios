import AuthenticationServices
import BitwardenKit
import Foundation
import XCTest

@testable import BitwardenShared

@available(iOS 26.4, *)
final class CXFPasskeyPRFFixturesTests: BitwardenTestCase {
    func test_validFixture_decodesThroughAuthenticationServices() throws {
        let (account, passkeys) = try decode(.valid)
        let passkey = try XCTUnwrap(passkeys.first)

        XCTAssertEqual(passkeys.count, 1)
        XCTAssertTrue(
            CXFPasskeyPRFMatcher.passkeyMatches(passkey, CXFPasskeyPRFFixtures.validPasskey),
            "Valid passkey mismatch; credential material redacted",
        )

        let dump = account.dump()
        XCTAssertTrue(dump.contains("Key: <redacted;"))
        XCTAssertTrue(dump.contains("CredentialWithUV: <redacted;"))
        XCTAssertTrue(dump.contains("CredentialWithoutUV: <redacted;"))
        XCTAssertFalse(dump.contains("Key: \(passkey.key)"))
        XCTAssertFalse(dump.contains(passkey.key.base64EncodedString()))
        let uvSeed = try XCTUnwrap(passkey.fido2Extensions?.hmacCredentials?.credentialWithUV)
        XCTAssertFalse(dump.contains(uvSeed.base64EncodedString()))
    }

    func test_missingPRFFixture_decodesWithoutExtensionState() throws {
        let (_, passkeys) = try decode(.missingPRF)
        let passkey = try XCTUnwrap(passkeys.first)

        XCTAssertEqual(passkeys.count, 1)
        XCTAssertTrue(passkey.fido2Extensions == nil, "Missing-PRF fixture unexpectedly carried extension state")
        XCTAssertTrue(
            CXFPasskeyPRFMatcher.passkeyMatches(passkey, CXFPasskeyPRFFixtures.missingPRFPasskey),
            "Missing-PRF passkey mismatch; credential material redacted",
        )
    }

    func test_malformedSeedFixture_decodesForImportValidation() throws {
        let (_, passkeys) = try decode(.malformedSeed)
        let passkey = try XCTUnwrap(passkeys.first)
        let hmacCredential = try XCTUnwrap(passkey.fido2Extensions?.hmacCredentials)

        XCTAssertEqual(passkeys.count, 1)
        XCTAssertEqual(hmacCredential.credentialWithUV.count, 31)
        XCTAssertEqual(hmacCredential.credentialWithoutUV.count, 32)
        XCTAssertTrue(
            CXFPasskeyPRFMatcher.passkeyMatches(passkey, CXFPasskeyPRFFixtures.malformedSeedPasskey),
            "Malformed-seed passkey mismatch; credential material redacted",
        )
    }

    func test_duplicateFixture_decodesBothCredentials() throws {
        let (_, passkeys) = try decode(.duplicate)

        XCTAssertEqual(passkeys.count, 2)
        XCTAssertTrue(CXFPasskeyPRFMatcher.containsDuplicateCredentialID(passkeys))
        XCTAssertTrue(
            passkeys.allSatisfy {
                CXFPasskeyPRFMatcher.passkeyMatches($0, CXFPasskeyPRFFixtures.validPasskey)
            },
            "Duplicate passkey mismatch; credential material redacted",
        )
    }

    func test_unsupportedKeyFixture_decodesForAlgorithmValidation() throws {
        let (_, passkeys) = try decode(.unsupportedKey)
        let passkey = try XCTUnwrap(passkeys.first)

        XCTAssertEqual(passkeys.count, 1)
        XCTAssertFalse(
            CXFPasskeyPRFMatcher.secretDataMatches(passkey.key, CXFPasskeyPRFFixtures.validPasskey.key),
            "Unsupported and ES256 fixture keys unexpectedly match; key material redacted",
        )
        XCTAssertTrue(
            CXFPasskeyPRFMatcher.passkeyMatches(passkey, CXFPasskeyPRFFixtures.unsupportedKeyPasskey),
            "Unsupported-key passkey mismatch; credential material redacted",
        )
    }

    func test_secretMatcher_comparesWithoutFormattingInputs() {
        let expected = Data(repeating: 0x11, count: 32)
        let different = Data(repeating: 0x22, count: 32)

        XCTAssertTrue(CXFPasskeyPRFMatcher.secretDataMatches(expected, expected))
        XCTAssertFalse(CXFPasskeyPRFMatcher.secretDataMatches(expected, different))
        XCTAssertFalse(CXFPasskeyPRFMatcher.secretDataMatches(expected, Data(different.dropLast())))
    }

    private func decode(
        _ scenario: CXFPasskeyPRFFixtures.Scenario,
    ) throws -> (ASImportableAccount, [ASImportableCredential.Passkey]) {
        let encoded = try JSONEncoder.cxfEncoder.encode(CXFPasskeyPRFFixtures.account(for: scenario))
        let account = try JSONDecoder.cxfDecoder.decode(ASImportableAccount.self, from: encoded)
        let passkeys = account.items.flatMap { item in
            item.credentials.compactMap { credential in
                guard case let .passkey(passkey) = credential else { return nil }
                return passkey
            }
        }
        return (account, passkeys)
    }
}
