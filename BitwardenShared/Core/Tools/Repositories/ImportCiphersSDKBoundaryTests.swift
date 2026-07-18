import BitwardenSdk
import CryptoKit
import Foundation
import TestHelpers
import XCTest

@testable import BitwardenShared

/// Exercises the real Nuri SDK from Apple's CXF model through encrypted cipher creation.
@available(iOS 26.4, *)
final class ImportCiphersSDKBoundaryTests: XCTestCase {
    @MainActor
    func test_importCxf_preservesCompleteSyntheticPasskeyThroughBlobSync() async throws {
        let client = try await initializedClient()
        let fixtureAccount = CXFPasskeyPRFFixtures.account(for: .valid)
        let fixtureData = try JSONEncoder.cxfEncoder.encode(fixtureAccount)
        let fixturePayload = try XCTUnwrap(String(data: fixtureData, encoding: .utf8))

        let importedCiphers = try client.exporters().importCxf(payload: fixturePayload)
        let importedCipher = try XCTUnwrap(importedCiphers.first)
        let importedCredential = try XCTUnwrap(importedCipher.login?.fido2Credentials?.first)
        XCTAssertNotNil(
            importedCredential.extensionState,
            "SDK import omitted encrypted FIDO2 extension state; value redacted",
        )

        let sdkVaultClient: BitwardenSdk.VaultClient = client.vault()
        let ciphersClient: BitwardenSdk.CiphersClient = sdkVaultClient.ciphers()
        let importedView = try await ciphersClient.decrypt(cipher: importedCipher)
        let encryptedContext = try await ciphersClient.encrypt(cipherView: importedView)
        let blobCipher = encryptedContext.cipher
        let blobData = try XCTUnwrap(blobCipher.data)
        let blobKey = try XCTUnwrap(blobCipher.key)
        try assertBlobV1Shape(blobData)
        XCTAssertNil(blobCipher.login)

        try assertImportRequestPreservesBlob(blobCipher, expectedBlobData: blobData)
        let persistedCipher = try await persistOfficialServerBlob(blobData: blobData, blobKey: blobKey)
        XCTAssertEqual(persistedCipher.data, blobData)
        XCTAssertNil(persistedCipher.login)
        XCTAssertNil(persistedCipher.name)

        let syncedView = try await ciphersClient.decrypt(cipher: persistedCipher)
        XCTAssertNotNil(
            syncedView.login?.fido2Credentials?.first?.extensionState,
            "Blob decrypt after sync mapping omitted extension state; value redacted",
        )
        try await assertPortablePasskey(client: client, syncedView: syncedView)
    }

    @MainActor
    private func initializedClient() async throws -> Client {
        let client = Client(tokenProvider: SDKBoundaryTokenProvider(), settings: nil)
        try await client.crypto().initializeUserCrypto(
            req: InitUserCryptoRequest(
                userId: "62dbb4dc-6e5f-4bc8-8b78-c946ebfe5308",
                kdfParams: .pbkdf2(iterations: 100_000),
                email: "synthetic@nuri.test",
                accountCryptographicState: .v2(
                    privateKey: syntheticV2PrivateKey(),
                    signedPublicKey: nil,
                    signingKey: syntheticV2SigningKey(),
                    securityState: syntheticV2SecurityState(),
                ),
                method: .decryptedKey(decryptedUserKey: syntheticV2UserKey()),
                upgradeToken: nil,
            ),
        )
        return client
    }

    private func assertImportRequestPreservesBlob(
        _ cipher: BitwardenSdk.Cipher,
        expectedBlobData: String,
    ) throws {
        let importRequest = try ImportCiphersRequest(ciphers: [cipher])
        let requestCipher = try XCTUnwrap(importRequest.body?.ciphers.first)
        let encodedRequestCipher = try JSONEncoder().encode(requestCipher)
        let requestJSON = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encodedRequestCipher) as? [String: Any],
        )
        XCTAssertEqual(requestJSON["data"] as? String, expectedBlobData)
        XCTAssertNil(requestJSON["login"])
        let requestPayload = try XCTUnwrap(String(bytes: encodedRequestCipher, encoding: .utf8))
        XCTAssertFalse(requestPayload.contains("extensionState"))
    }

    @MainActor
    private func persistOfficialServerBlob(blobData: String, blobKey: String) async throws -> BitwardenSdk.Cipher {
        let cipherDataStore = MockCipherDataStore()
        let apiService = APIService(client: MockHTTPClient())
        let cipherService = DefaultCipherService(
            cipherAPIService: apiService,
            cipherDataStore: cipherDataStore,
            fileAPIService: apiService,
            stateService: MockStateService(),
        )
        try await cipherService.replaceCiphers(
            [serverResponse(blobData: blobData, blobKey: blobKey)],
            userId: "62dbb4dc-6e5f-4bc8-8b78-c946ebfe5308",
        )
        return try XCTUnwrap(cipherDataStore.replaceCiphersValue?.first)
    }

    private func assertPortablePasskey(
        client: Client,
        syncedView: BitwardenSdk.CipherView,
    ) async throws {
        let clientDataHash = Data(repeating: 0xA5, count: 32)
        let authenticator = client.platform().fido2().authenticator(
            userInterface: SDKBoundaryUserInterface(),
            credentialStore: SDKBoundaryCredentialStore(cipher: syncedView),
        )
        let result = try await authenticator.getAssertion(
            request: portablePasskeyRequest(clientDataHash: clientDataHash),
        )

        XCTAssertTrue(
            CXFPasskeyPRFMatcher.secretDataMatches(result.credentialId, Data(0x00 ... 0x1F)),
            "Credential ID changed across BlobV1 sync; value redacted",
        )
        XCTAssertTrue(
            CXFPasskeyPRFMatcher.secretDataMatches(result.userHandle, Data(0x20 ... 0x2F)),
            "User handle changed across BlobV1 sync; value redacted",
        )
        let prfResults = try XCTUnwrap(result.extensions.prf?.results)
        XCTAssertTrue(
            CXFPasskeyPRFMatcher.secretDataMatches(
                prfResults.first,
                decodeBase64URL("d8i94nf9OSyRco1LXP3wnUrRte5rCmguP3cURrj06go"),
            ),
            "First PRF output changed across BlobV1 sync; value redacted",
        )
        XCTAssertTrue(
            prfResults.second.map {
                CXFPasskeyPRFMatcher.secretDataMatches(
                    $0,
                    decodeBase64URL("wxVdw-_rf1oJwrVQn-r6p4nqgf_dJgsfBDutwJNqdEY"),
                )
            } ?? false,
            "Second PRF output changed across BlobV1 sync; value redacted",
        )
        XCTAssertTrue(
            authenticatorDataMatchesFixture(result.authenticatorData),
            "Authenticator data lost RP, presence, verification, or counter semantics; value redacted",
        )
        XCTAssertTrue(
            signatureIsValid(result, clientDataHash: clientDataHash),
            "Imported private key did not produce the expected valid signature; value redacted",
        )
    }

    private func portablePasskeyRequest(clientDataHash: Data) -> GetAssertionRequest {
        GetAssertionRequest(
            rpId: "nuri.com",
            clientDataHash: clientDataHash,
            allowList: nil,
            options: Options(rk: true, uv: .discouraged),
            extensions: GetAssertionExtensionsInput(
                prf: GetAssertionPrfInput(
                    eval: PrfInputValues(
                        first: Data("nuri-prf-salt-v1".utf8),
                        second: Data("test-salt-2".utf8),
                        alreadyHashed: false,
                    ),
                    evalByCredential: nil,
                ),
            ),
        )
    }

    private func authenticatorDataMatchesFixture(_ authenticatorData: Data) -> Bool {
        guard authenticatorData.count >= 37 else { return false }
        let expectedRPHash = Data(SHA256.hash(data: Data("nuri.com".utf8)))
        let flags = authenticatorData[32]
        let counter = authenticatorData[33 ..< 37]
        return CXFPasskeyPRFMatcher.secretDataMatches(authenticatorData.prefix(32), expectedRPHash)
            && flags & 0x01 != 0
            && flags & 0x04 != 0
            && counter.allSatisfy { $0 == 0 }
    }

    private func signatureIsValid(_ result: GetAssertionResult, clientDataHash: Data) -> Bool {
        let encodedPublicKey = [
            "BP6-odPIQNL1AE02LYE0vK7pO6e5slP8vcbeLsoukQOEwPXmGLbgiMYEfRDKUkiu-",
            "VPgk3a11EYXjfpcZz5WgCU",
        ].joined()
        guard let publicKey = try? P256.Signing.PublicKey(
            x963Representation: decodeBase64URL(encodedPublicKey),
        ),
            let signature = try? P256.Signing.ECDSASignature(derRepresentation: result.signature)
        else {
            return false
        }
        return publicKey.isValidSignature(signature, for: result.authenticatorData + clientDataHash)
    }

    private func decodeBase64URL(_ value: String) -> Data {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))
        return Data(base64Encoded: base64) ?? Data()
    }

    private func assertBlobV1Shape(_ opaqueData: String) throws {
        let blob = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(opaqueData.utf8)) as? [String: Any],
        )
        XCTAssertEqual(Set(blob.keys), ["format_version", "wrapped_cek", "envelope"])
        XCTAssertEqual(blob["format_version"] as? Int, 1)
        XCTAssertFalse(try XCTUnwrap(blob["wrapped_cek"] as? String).isEmpty)
        let envelope = try XCTUnwrap(blob["envelope"] as? String)
        XCTAssertNotNil(Data(base64Encoded: envelope))
    }

    private func serverResponse(blobData: String, blobKey: String) throws -> CipherDetailsResponseModel {
        let responseData = try JSONSerialization.data(withJSONObject: [
            "collectionIds": [],
            "creationDate": "2026-07-18T10:00:00Z",
            "data": blobData,
            "edit": true,
            "favorite": false,
            "id": "4c862f31-0303-4d19-8bc8-0a7f5028400f",
            "key": blobKey,
            "name": NSNull(),
            "organizationUseTotp": false,
            "reprompt": 0,
            "revisionDate": "2026-07-18T10:00:00Z",
            "type": 1,
            "viewPassword": true,
        ])
        return try CipherDetailsResponseModel.decoder.decode(
            CipherDetailsResponseModel.self,
            from: responseData,
        )
    }

    // Public V2 compatibility vectors copied byte-for-byte from sdk-internal@ac6eb96, the commit
    // behind the pinned Swift package. They are deterministic test material, never account secrets.
    private func syntheticV2UserKey() -> String {
        "pQEEAlACHUUoybNAuJoZzqNMxz2bAzoAARFvBIQDBAUGIFggAvGl4ifaUAomQdCdUPpXLHtypiQxHjZwRHeI83caZM4B"
    }

    private func syntheticV2PrivateKey() -> String {
        """
        7.g1gdowE6AAERbwMZARwEUAIdRSjJs0C4mhnOo0zHPZuhBVgYthGLGqVLPeidY8mNMxpLJn3fyeSxyaWsWQTR6pxmRV2DyGZXly
        /0l9KK+Rsfetl9wvYIz0O4/RW3R6wf7eGxo5XmicV3WnFsoAmIQObxkKWShxFyjzg+ocKItQDzG7Gp6+MW4biTrAlfK51ML/ZS+P
        CjLmgI1QQr4eMHjiwA2TBKtKkxfjoTJkMXECpRVLEXOo8/mbIGYkuabbSA7oU+TJ0yXlfKDtD25gnyO7tjW/0JMFUaoEKRJOuKoX
        TN4n/ks4Hbxk0X5/DzfG05rxWad2UNBjNg7ehW99WrQ+33ckdQFKMQOri/rt8JzzrF1k11/jMJ+Y2TADKNHr91NalnUX+yqZAAe3
        sRt5Pv5ZhLIwRMKQi/1NrLcsQPRuUnogVSPOoMnE/eD6F70iU60Z6pvm1iBw2IvELZcrs/oxpO2SeCue08fIZW/jNZokbLnm90tQ
        7QeZTUpiPALhUgfGOa3J9VOJ7jQGCqDjd9CzV2DCVfhKCapeTbldm+RwEWBz5VvorH5vMx1AzbPRJxdIQuxcg3NqRrXrYC7fyZlj
        WaPB9qP1tztiPtd1PpGEgxLByIfR6fqyZMCvOBsWbd0H6NhF8mNVdDw60+skFRdbRBTSCjCtKZeLVuVFb8ioH45PR5oXjtx4atID
        zu6DKm6TTMCbR6DjZuZZ8GbwHxuUD2mDD3pAFhaof9kR3lQdjy7Zb4EzUUYskQxzcLPcqzp9ZgB3Rg91SStBCCMhdQ6AnhTy+VTG
        t/mY5AbBXNRSL6fI0r+P9K8CcEI4bNZCDkwwQr5v4O4ykSUzIvmVU0zKzDngy9bteIZuhkvGUoZlQ9UATNGPhoLfqq2eSvqEXkCb
        xTVZ5D+Ww9pHmWeVcvoBhcl5MvicfeQt++dY3tPjIfZq87nlugG4HiNbcv9nbVpgwe3v8cFetWXQgnO4uhx8JHSwGoSuxHFZtl2s
        dahjTHavRHnYjSABEFrViUKgb12UDD5ow1GAL62wVdSJKRf9HlLbJhN3PBxuh5L/E0wy1wGA9ecXtw/R1ktvXZ7RklGAt1TmNzZv
        6vI2J/CMXvndOX9rEpjKMbwbIDAjQ9PxiWdcnmc5SowT9f6yfIjbjXnRMWWidPAua7sgrtej4HP4Qjz1fpgLMLCRyF97tbMTmsAI
        5Cuj98Buh9PwcdyXj5SbVuHdJS1ehv9b5SWPsD4pwOm3+otVNK6FTazhoUl47AZoAoQzXfsXxrzqYzvF0yJkCnk9S1dcij1L569g
        Q43CJO6o6jIZFJvA4EmZDl95ELu+BC+x37Ip8dq4JLPsANDVSqvXO9tfDUIXEx25AaOYhW2KAUoDve/fbsU8d0UZR1o/w+ZrOQwa
        wCIPeVPtbh7KFRVQi/rPI+Abl6XR6qMJbKPegliYGUuGF2oEMEc6QLTsMRCEPuw0S3kxbNfVPqml8nGhB2r8zUHBY1diJEmipVgh
        nwH74gIKnyJ2C9nKjV8noUfKzqyV8vxUX2G5yXgodx8Jn0cWs3XhWuApFla9z4R28W/4jA1jK2WQMlx+b6xKUWgRk8+fYsc0HSt2
        fDrQ9pLpnjb8ME59RCxSPV++PThpnR2JtastZBZur2hBIJsGILCAmufUU4VC4gBKPhNfu/OK4Ktgz+uQlUa9fEC/FnkpTRQPxHuQ
        jSQSNrIIyW1bIRBtnwjvvvNoui9FZJ
        """.replacingOccurrences(of: "\n", with: "")
    }

    private func syntheticV2SigningKey() -> String {
        """
        7.g1gcowE6AAERbwMYZQRQAh1FKMmzQLiaGc6jTMc9m6EFWBhYePc2qkCruHAPXgbzXsIP1WVk11ArbLNYUBpifToURlwHKs1je2
        BwZ1C/5thz4nyNbL0wDaYkRWI9ex1wvB7KhdzC7ltStEd5QttboTSCaXQROSZaGBPNO5+Bu3sTY8F5qK1pBUo6AHNN
        """.replacingOccurrences(of: "\n", with: "")
    }

    private func syntheticV2SecurityState() -> String {
        """
        hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8CoFgkomhlbnRpdHlJZFBHOOw2BI9OQoNq+Vl1xZZKZ3ZlcnNpb24CWEAl
        chbJR0vmRfShG8On7Q2gknjkw4Dd6MYBLiH4u+/CmfQdmjNZdf6kozgW/6NXyKVNu8dAsKsin+xxXkDyVZoG
        """.replacingOccurrences(of: "\n", with: "")
    }
}

private final class SDKBoundaryTokenProvider: ClientManagedTokens, @unchecked Sendable {
    func getAccessToken() async -> String? { nil }
}

private final class SDKBoundaryCredentialStore: Fido2CredentialStore, @unchecked Sendable {
    private let cipher: BitwardenSdk.CipherView

    init(cipher: BitwardenSdk.CipherView) {
        self.cipher = cipher
    }

    func findCredentials(ids: [Data]?, ripId: String, userHandle: Data?) async throws -> [BitwardenSdk.CipherView] {
        [cipher]
    }

    func allCredentials() async throws -> [BitwardenSdk.CipherListView] {
        []
    }

    func saveCredential(cred: BitwardenSdk.EncryptionContext) async throws {
        throw SDKBoundaryFido2Error.unexpectedSave
    }
}

private final class SDKBoundaryUserInterface: Fido2UserInterface, @unchecked Sendable {
    func checkUser(options: CheckUserOptions, hint: UiHint) async throws -> CheckUserResult {
        guard options.requireVerification == .required else {
            throw SDKBoundaryFido2Error.prfDidNotRequireVerification
        }
        return CheckUserResult(userPresent: true, userVerified: true)
    }

    func pickCredentialForAuthentication(
        availableCredentials: [BitwardenSdk.CipherView],
    ) async throws -> BitwardenSdk.CipherViewWrapper {
        guard let cipher = availableCredentials.first else {
            throw SDKBoundaryFido2Error.missingCredential
        }
        return BitwardenSdk.CipherViewWrapper(cipher: cipher)
    }

    func checkUserAndPickCredentialForCreation(
        options: CheckUserOptions,
        newCredential: Fido2CredentialNewView,
    ) async throws -> CheckUserAndPickCredentialForCreationResult {
        throw SDKBoundaryFido2Error.unexpectedCreation
    }

    func isVerificationEnabled() -> Bool { true }
}

private enum SDKBoundaryFido2Error: Error {
    case missingCredential
    case prfDidNotRequireVerification
    case unexpectedCreation
    case unexpectedSave
}
