import AuthenticationServices
import BitwardenSdk
import Foundation
import XCTest

@testable import BitwardenShared

/// Exercises the real Nuri SDK from Apple's CXF model through encrypted cipher creation.
@available(iOS 26.4, *)
final class ImportCiphersSDKBoundaryTests: XCTestCase {
    func test_importCxf_preservesCompleteSyntheticPasskey() async throws {
        let client = Client(tokenProvider: SDKBoundaryTokenProvider(), settings: nil)
        try await client.crypto().initializeUserCrypto(
            req: InitUserCryptoRequest(
                userId: "62dbb4dc-6e5f-4bc8-8b78-c946ebfe5308",
                kdfParams: .pbkdf2(iterations: 100_000),
                email: "synthetic@nuri.test",
                accountCryptographicState: .v1(privateKey: syntheticEncryptedPrivateKey()),
                method: .decryptedKey(decryptedUserKey: syntheticUserKey()),
                upgradeToken: nil,
            ),
        )

        let fixtureAccount = CXFPasskeyPRFFixtures.account(for: .valid)
        let fixtureData = try JSONEncoder.cxfEncoder.encode(fixtureAccount)
        let fixturePayload = try XCTUnwrap(String(data: fixtureData, encoding: .utf8))

        let importedCiphers = try client.exporters().importCxf(payload: fixturePayload)
        let importedCredential = try XCTUnwrap(
            importedCiphers.first?.login?.fido2Credentials?.first,
        )
        XCTAssertNotNil(
            importedCredential.extensionState,
            "SDK import omitted encrypted FIDO2 extension state; value redacted",
        )

        // SDK export is used only as a test oracle to decrypt the just-imported cipher.
        let oraclePayload = try client.exporters().exportCxf(
            account: BitwardenSdk.Account(
                id: "62dbb4dc-6e5f-4bc8-8b78-c946ebfe5308",
                email: "synthetic@nuri.test",
                name: "Synthetic Nuri Test",
            ),
            ciphers: importedCiphers,
        )
        let oracleAccount = try JSONDecoder.cxfDecoder.decode(
            ASImportableAccount.self,
            from: Data(oraclePayload.utf8),
        )
        let oraclePasskey = try XCTUnwrap(passkeys(in: oracleAccount).first)

        XCTAssertTrue(
            CXFPasskeyPRFMatcher.passkeyMatches(
                oraclePasskey,
                CXFPasskeyPRFFixtures.validPasskey,
            ),
            "Complete passkey changed across real SDK import; credential material redacted",
        )
    }

    private func passkeys(in account: ASImportableAccount) -> [ASImportableCredential.Passkey] {
        account.items.flatMap { item in
            item.credentials.compactMap { credential in
                guard case let .passkey(passkey) = credential else { return nil }
                return passkey
            }
        }
    }

    private func syntheticEncryptedPrivateKey() -> String {
        let initializationVector = Data(repeating: 0x31, count: 16).base64EncodedString()
        let ciphertext = Data(repeating: 0x32, count: 16).base64EncodedString()
        let mac = Data(repeating: 0x33, count: 32).base64EncodedString()
        return "2.\(initializationVector)|\(ciphertext)|\(mac)"
    }

    private func syntheticUserKey() -> String {
        Data(repeating: 0x41, count: 64).base64EncodedString()
    }
}

private final class SDKBoundaryTokenProvider: ClientManagedTokens, @unchecked Sendable {
    func getAccessToken() async -> String? { nil }
}
