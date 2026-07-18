// swiftlint:disable:this file_name

import AuthenticationServices
import Foundation

/// Synthetic passkey fixtures for the iOS Credential Exchange PRF import boundary.
///
/// Every byte is public test material from the Nuri CXF conformance vector. Never replace
/// these values with credential material exported from a real account.
@available(iOS 26.4, *)
enum CXFPasskeyPRFFixtures {
    enum Scenario: CaseIterable {
        case valid
        case missingPRF
        case malformedSeed
        case duplicate
        case unsupportedKey
    }

    static let validPasskey = makePasskey(
        key: decodeBase64URL(
            // swiftlint:disable:next line_length
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPzvtWYWmIsvqqr3LsZB0K-cbjuhJSGTGziL1LksHAPShRANCAAT-vqHTyEDS9QBNNi2BNLyu6TunubJT_L3G3i7KLpEDhMD15hi24IjGBH0QylJIrvlT4JN2tdRGF436XGc-VoAl",
        ),
        hmacCredential: makeHMACCredential(),
    )

    static let missingPRFPasskey = makePasskey(
        key: validPasskey.key,
        hmacCredential: nil,
    )

    static let malformedSeedPasskey = makePasskey(
        key: validPasskey.key,
        hmacCredential: makeHMACCredential(
            credentialWithUV: Data(repeating: 0x11, count: 31),
        ),
    )

    static let unsupportedKeyPasskey = makePasskey(
        key: decodeBase64URL("MC4CAQAwBQYDK2VwBCIEIDMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz"),
        hmacCredential: makeHMACCredential(),
    )

    /// Returns an Apple AuthenticationServices account for the requested negative or positive case.
    static func account(for scenario: Scenario) -> ASImportableAccount {
        let passkeys: [ASImportableCredential.Passkey] = switch scenario {
        case .valid:
            [validPasskey]
        case .missingPRF:
            [missingPRFPasskey]
        case .malformedSeed:
            [malformedSeedPasskey]
        case .duplicate:
            [validPasskey, validPasskey]
        case .unsupportedKey:
            [unsupportedKeyPasskey]
        }

        return ASImportableAccount.fixture(
            id: Data("synthetic-account-v1".utf8),
            userName: "synthetic@nuri.test",
            email: "synthetic@nuri.test",
            fullName: "Synthetic Nuri Test",
            items: [
                .fixture(
                    id: Data("synthetic-item-v1".utf8),
                    created: Date(timeIntervalSince1970: 1_735_689_600),
                    lastModified: Date(timeIntervalSince1970: 1_735_689_600),
                    title: "Synthetic Nuri PRF Passkey",
                    subtitle: "Deterministic interoperability test vector",
                    credentials: passkeys.map(ASImportableCredential.passkey),
                    tags: ["synthetic", "passkey", "prf"],
                ),
            ],
        )
    }

    private static func makeHMACCredential(
        credentialWithUV: Data = Data(repeating: 0x11, count: 32),
        credentialWithoutUV: Data = Data(repeating: 0x22, count: 32),
    ) -> ASImportableFIDO2HMACCredential {
        ASImportableFIDO2HMACCredential(
            algorithm: .sha256,
            credentialWithUV: credentialWithUV,
            credentialWithoutUV: credentialWithoutUV,
        )
    }

    private static func makePasskey(
        key: Data,
        hmacCredential: ASImportableFIDO2HMACCredential?,
    ) -> ASImportableCredential.Passkey {
        ASImportableCredential.Passkey(
            credentialID: Data(0x00 ... 0x1F),
            relyingPartyIdentifier: "nuri.com",
            userName: "synthetic@nuri.test",
            userDisplayName: "Synthetic Nuri User",
            userHandle: Data(0x20 ... 0x2F),
            key: key,
            fido2Extensions: hmacCredential.map {
                ASImportableFIDO2Extensions(hmacCredentials: $0, largeBlob: nil)
            },
        )
    }

    private static func decodeBase64URL(_ value: String) -> Data {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64.append(String(repeating: "=", count: (4 - base64.count % 4) % 4))

        guard let data = Data(base64Encoded: base64) else {
            preconditionFailure("Invalid embedded synthetic fixture")
        }
        return data
    }
}

/// Public, deterministic BlobV1 container from sdk-internal@ac6eb96's compatibility test.
/// It contains no real account or credential material.
enum CipherBlobV1Fixtures {
    static let recordedSDKBlob = [
        "{\"format_version\":1,\"wrapped_cek\":\"",
        "2.LQJf2BbznXX+NelBY4pSJg==|txMmjZEOhSMA7Jrm+rZt1LDfA6s3G2QU5Z8MqO4nG9s2ZXuzSLU/",
        "iYOUXD8xw+eHVSu7IUHu1LsCm4SLf+ZhkX5QIo4hJT3DHSbgu6VPUC0=|yuU/EWQWyihf2Yh9lQ1NP+zTROEpnXoR",
        "S//GfxDgC4k=\",\"envelope\":\"",
        "g1hLpQE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLmNib3ItcGFkZGVkBFBoHnjLne8MPV72YPXuskd6",
        "OgABOIECOgABOIABoQVYGA00vxb7gF7Y3SUyoCMy34C1HrB3fSY3jVhxZXQmmotGEIwwRlG+SpTcyTl5m4lUnozWr",
        "jAYfWitl1+cz457Wq3iDW/MvrHE7c1g38QJxY6t1yhQL0dQy9DyDXQDiWGPtYzic2Ay+GtrlIERN37wOdhQ1HZDeo",
        "obHL+aKomvPTems/Ta2SqWC9HfE38=\"}",
    ].joined()
}

/// Matchers for imported passkey fixtures that never interpolate secret bytes into failures.
@available(iOS 26.4, *)
enum CXFPasskeyPRFMatcher {
    /// Compares arbitrary secret buffers without constructing a printable representation.
    static func secretDataMatches(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }

        var difference: UInt8 = 0
        for (left, right) in zip(lhs, rhs) {
            difference |= left ^ right
        }
        return difference == 0
    }

    /// Compares the complete synthetic passkey while keeping key and HMAC bytes out of diagnostics.
    static func passkeyMatches(
        _ lhs: ASImportableCredential.Passkey,
        _ rhs: ASImportableCredential.Passkey,
    ) -> Bool {
        guard secretDataMatches(lhs.credentialID, rhs.credentialID),
              lhs.relyingPartyIdentifier == rhs.relyingPartyIdentifier,
              lhs.userName == rhs.userName,
              lhs.userDisplayName == rhs.userDisplayName,
              secretDataMatches(lhs.userHandle, rhs.userHandle),
              secretDataMatches(lhs.key, rhs.key)
        else {
            return false
        }

        switch (lhs.fido2Extensions?.hmacCredentials, rhs.fido2Extensions?.hmacCredentials) {
        case (nil, nil):
            return true
        case let (left?, right?):
            return left.algorithm == right.algorithm
                && secretDataMatches(left.credentialWithUV, right.credentialWithUV)
                && secretDataMatches(left.credentialWithoutUV, right.credentialWithoutUV)
        default:
            return false
        }
    }

    /// Detects duplicate credential IDs without formatting an ID into a test failure.
    static func containsDuplicateCredentialID(_ passkeys: [ASImportableCredential.Passkey]) -> Bool {
        var credentialIDs = Set<Data>()
        for passkey in passkeys where !credentialIDs.insert(passkey.credentialID).inserted {
            return true
        }
        return false
    }
}
