import Foundation
import XCTest

@testable import BitwardenShared
@testable import BitwardenSharedMocks

// MARK: - ImportCiphersRequestTests

class ImportCiphersRequestTests: BitwardenTestCase {
    // MARK: Tests

    /// `init(ciphers:folders:folderRelationships:)` initializes the request successfully.
    func test_init() throws {
        let subject = try ImportCiphersRequest(
            ciphers: [.fixture(name: "cipherTest")],
            folders: [.fixture(name: "folderTest")],
            folderRelationships: [(1, 1)],
        )
        XCTAssertEqual(subject.body?.ciphers[0].name, "cipherTest")
        XCTAssertEqual(subject.body?.folders[0].name, "folderTest")
        XCTAssertEqual(subject.body?.folderRelationships[0].key, 1)
        XCTAssertEqual(subject.body?.folderRelationships[0].value, 1)
    }

    /// `init(ciphers:folders:folderRelationships:)` sends composite ciphers only through the
    /// official opaque `data` property, without legacy login or extension fields.
    func test_init_compositeCipherUsesOpaqueData() throws {
        let opaqueCipherData = "2.c3ludGhldGljLWJsb2I="
        let subject = try ImportCiphersRequest(
            ciphers: [.fixture(data: opaqueCipherData, login: nil, type: .login)],
        )

        let cipher = try XCTUnwrap(subject.body?.ciphers.first)
        XCTAssertEqual(cipher.data, opaqueCipherData)
        XCTAssertNil(cipher.login)
        XCTAssertFalse(cipher.name.isEmpty, "Official import validation still requires an encrypted name")

        let encodedCipher = try JSONEncoder().encode(cipher)
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: encodedCipher) as? [String: Any],
        )
        XCTAssertEqual(json["data"] as? String, opaqueCipherData)
        XCTAssertNil(json["login"])
        XCTAssertFalse(String(decoding: encodedCipher, as: UTF8.self).contains("extensionState"))
    }

    /// `init(ciphers:folders:folderRelationships:)` initializes the request successfully.
    func test_init_throws() throws {
        XCTAssertThrowsError(_ = try ImportCiphersRequest(
            ciphers: [],
        ))
    }

    /// `path` returns the correct path.
    func test_path() throws {
        let subject = try ImportCiphersRequest(ciphers: [.fixture()])
        XCTAssertEqual(subject.path, "/ciphers/import")
    }

    /// `method` is `.put`.
    func test_method() throws {
        let subject = try ImportCiphersRequest(ciphers: [.fixture()])
        XCTAssertEqual(subject.method, .post)
    }
}
