import AuthenticationServices
import BitwardenKit
import Foundation
import XCTest

@testable import BitwardenShared

@available(iOS 26.4, *)
final class CXFPasskeyPRFFixturesTests: BitwardenTestCase {
    func test_recordedSDKBlob_hasOfficialBlobV1Shape() throws {
        let blob = try XCTUnwrap(
            JSONSerialization.jsonObject(
                with: Data(CipherBlobV1Fixtures.recordedSDKBlob.utf8),
            ) as? [String: Any],
        )

        XCTAssertEqual(Set(blob.keys), ["format_version", "wrapped_cek", "envelope"])
        XCTAssertEqual(blob["format_version"] as? Int, 1)
        XCTAssertFalse(try XCTUnwrap(blob["wrapped_cek"] as? String).isEmpty)
        let envelope = try XCTUnwrap(blob["envelope"] as? String)
        XCTAssertNotNil(Data(base64Encoded: envelope))
    }

    func test_validFixture_decodesThroughAuthenticationServices() throws {
        let (account, passkeys) = try decode(.valid)
        let passkey = try XCTUnwrap(passkeys.first)

        XCTAssertEqual(passkeys.count, 1)
        XCTAssertTrue(
            CXFPasskeyPRFMatcher.passkeyMatches(passkey, CXFPasskeyPRFFixtures.validPasskey),
            "Valid passkey mismatch; credential material redacted",
        )

        let dump = account.dump()
        let hmacCredential = try XCTUnwrap(passkey.fido2Extensions?.hmacCredentials)
        XCTAssertTrue(dump.contains("Key: <redacted; \(passkey.key.count) bytes>"))
        XCTAssertTrue(
            dump.contains("CredentialWithUV: <redacted; \(hmacCredential.credentialWithUV.count) bytes>"),
        )
        XCTAssertTrue(
            dump.contains(
                "CredentialWithoutUV: <redacted; \(hmacCredential.credentialWithoutUV.count) bytes>",
            ),
        )
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
        var passkeys = [ASImportableCredential.Passkey]()
        for item in account.items {
            for credential in item.credentials {
                guard case let .passkey(passkey) = credential else { continue }
                passkeys.append(passkey)
            }
        }
        return (account, passkeys)
    }
}
