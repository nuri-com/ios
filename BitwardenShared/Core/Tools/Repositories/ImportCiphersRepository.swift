import AuthenticationServices
import BitwardenSdk
import Foundation

/// A protocol for a `ImportCiphersRepository` which manages importing credentials needed by the UI layer.
///
protocol ImportCiphersRepository: AnyObject {
    /// Performs an API request to import ciphers in the vault.
    /// - Parameters:
    ///   - credentialImportToken: The token used in `ASCredentialImportManager` to get the credentials to import.
    ///   - onProgress: Closure to update progress.
    /// - Returns: A dictionary containing the localized cipher type (key) and count (value) of that type
    /// that was imported, e.g. ["Passwords": 3, "Cards": 2].
    @available(iOS 26.0, *)
    func importCiphers(
        credentialImportToken: UUID,
        onProgress: @MainActor (Double) -> Void,
    ) async throws -> [CXFCredentialsResult]
}

// MARK: - DefaultImportCiphersRepository

/// A default implementation of a `ImportCiphersRepository`.
///
class DefaultImportCiphersRepository {
    // MARK: Properties

    /// The service that handles common client functionality such as encryption and decryption.
    let clientService: ClientService

    /// The factory to create credential managers.
    let credentialManagerFactory: CredentialManagerFactory

    /// Builder to be used to create helper objects for the Credential Exchange flow.
    let cxfCredentialsResultBuilder: CXFCredentialsResultBuilder

    /// The service that manages importing credentials.
    let importCiphersService: ImportCiphersService

    /// The service used to handle syncing vault data with the API.
    let syncService: SyncService

    // MARK: Initialization

    /// Initialize a `DefaultImportCiphersRepository`
    ///
    /// - Parameters:
    ///   - clientService: The service that handles common client functionality such as encryption and decryption.
    ///   - credentialManagerFactory: A factory to create credential managers.
    ///   - cxfCredentialsResultBuilder: Builder to be used to create helper objects for the Credential Exchange flow.
    ///   - importCiphersService: A service that manages importing credentials.
    ///   - syncService: The service used to handle syncing vault data with the API.
    ///
    init(
        clientService: ClientService,
        credentialManagerFactory: CredentialManagerFactory,
        cxfCredentialsResultBuilder: CXFCredentialsResultBuilder,
        importCiphersService: ImportCiphersService,
        syncService: SyncService,
    ) {
        self.clientService = clientService
        self.credentialManagerFactory = credentialManagerFactory
        self.cxfCredentialsResultBuilder = cxfCredentialsResultBuilder
        self.importCiphersService = importCiphersService
        self.syncService = syncService
    }
}

// MARK: ImportCiphersRepository

extension DefaultImportCiphersRepository: ImportCiphersRepository {
    @available(iOS 26.0, *)
    func importCiphers(
        credentialImportToken: UUID,
        onProgress: @MainActor (Double) -> Void,
    ) async throws -> [CXFCredentialsResult] {
        let credentialData = try await credentialManagerFactory.createImportManager().importCredentials(
            token: credentialImportToken,
        )
        guard let accountData = credentialData.accounts.first else {
            // this should never happen.
            throw ImportCiphersRepositoryError.noDataFound
        }

        let accountJsonData = try JSONEncoder.cxfEncoder.encode(accountData)
        guard let accountJsonString = String(data: accountJsonData, encoding: .utf8) else {
            // this should never happen.
            throw ImportCiphersRepositoryError.dataEncodingFailed
        }

        let importedCiphers: [Cipher]
        do {
            importedCiphers = try await clientService.exporters().importCxf(payload: accountJsonString)
        } catch {
            // SDK import failures can originate while parsing plaintext credential material.
            // Never forward the underlying error to telemetry because it may contain payload data.
            throw ImportCiphersRepositoryError.sdkImportFailed
        }

        let ciphers: [Cipher]
        do {
            let ciphersClient = try await clientService.vault().ciphers()
            var encryptedCiphers = [Cipher]()
            encryptedCiphers.reserveCapacity(importedCiphers.count)

            for importedCipher in importedCiphers {
                let containsPortablePasskey = importedCipher.login?.fido2Credentials?.contains {
                    $0.extensionState != nil
                } == true
                let cipherView = try await ciphersClient.decrypt(cipher: importedCipher)
                let encryptionContext = try await ciphersClient.encrypt(cipherView: cipherView)

                guard !containsPortablePasskey || encryptionContext.cipher.data != nil else {
                    throw ImportCiphersRepositoryError.blobCapableAccountRequired
                }

                let encryptedCipher = encryptionContext.cipher.withLegacyNameFallback(importedCipher.name)
                guard encryptedCipher.data == nil || encryptedCipher.name?.isEmpty == false else {
                    // The official import endpoint still validates the obsolete name property,
                    // even though it stores only the opaque data blob.
                    throw ImportCiphersRepositoryError.sdkImportFailed
                }
                encryptedCiphers.append(encryptedCipher)
            }
            ciphers = encryptedCiphers
        } catch let error as ImportCiphersRepositoryError {
            throw error
        } catch {
            // SDK crypto errors may include decrypted cipher details. Keep telemetry redacted.
            throw ImportCiphersRepositoryError.sdkImportFailed
        }

        await onProgress(0.3)

        _ = try await importCiphersService
            .importCiphers(
                ciphers: ciphers,
                folders: [],
                folderRelationships: [],
            )

        await onProgress(0.8)

        try await syncService.fetchSync(forceSync: true)

        // Blob-encrypted ciphers intentionally omit legacy fields, so count the SDK import result.
        let importedCredentialsCount = cxfCredentialsResultBuilder.build(from: importedCiphers)

        await onProgress(1.0)

        return importedCredentialsCount.filter { !$0.isEmpty }
    }
}

// MARK: - ImportCiphersRepositoryError

enum ImportCiphersRepositoryError: Error {
    case noDataFound
    case dataEncodingFailed
    case sdkImportFailed
    case blobCapableAccountRequired
}

private extension Cipher {
    /// Retains an encrypted legacy name solely to satisfy the official import endpoint's request
    /// validation. The server ignores this field whenever opaque composite `data` is present.
    func withLegacyNameFallback(_ fallbackName: String?) -> Cipher {
        guard name == nil, let fallbackName else { return self }
        return Cipher(
            id: id,
            organizationId: organizationId,
            folderId: folderId,
            collectionIds: collectionIds,
            key: key,
            name: fallbackName,
            notes: notes,
            type: type,
            login: login,
            identity: identity,
            card: card,
            secureNote: secureNote,
            sshKey: sshKey,
            bankAccount: bankAccount,
            driversLicense: driversLicense,
            passport: passport,
            favorite: favorite,
            reprompt: reprompt,
            organizationUseTotp: organizationUseTotp,
            edit: edit,
            permissions: permissions,
            viewPassword: viewPassword,
            localData: localData,
            attachments: attachments,
            fields: fields,
            passwordHistory: passwordHistory,
            creationDate: creationDate,
            deletedDate: deletedDate,
            revisionDate: revisionDate,
            archivedDate: archivedDate,
            data: data,
        )
    }
}
