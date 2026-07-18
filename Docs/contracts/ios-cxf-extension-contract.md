# iOS Credential Exchange (CXF) & FIDO2 Extension Contract

A mapping of how the iOS app handles Credential Exchange import/export flows and
where WebAuthn/FIDO2 extensions (PRF, hmac-secret) live in the codebase. This is a
reference map for agents and reviewers, not a specification — the source code is the
source of truth.

Corrected 2026-07-18 against Apple's current AuthenticationServices documentation.
The base Credential Exchange types start at iOS 26.0. Apple added
`ASImportableCredential.Passkey.fido2Extensions`, `ASImportableFIDO2Extensions`,
and `ASImportableFIDO2HMACCredential` in iOS 26.4.

---

## 1. Credential Exchange (CXF) — overview

CXF is Apple's `ASCredentialExchange*` protocol (iOS 26.0+) that lets password
managers import/export vaults via a system-mediated, token-based flow. The app
participates on both sides:

- **Import**: the system hands the app an `ASCredentialImportToken` via an
  `NSUserActivity` of type `ASCredentialExchangeActivity`. The app calls
  `ASCredentialImportManager.importCredentials(token:)` to get an
  `ASExportedCredentialData`, encodes it to CXF JSON, and feeds it to the Bitwarden
  SDK's `importCxf` exporter.
- **Export**: the app builds an `ASImportableAccount` from the vault (via the SDK's
  `exportCxf`), then hands it to `ASCredentialExportManager.exportCredentials(...)`
  wrapped in an `ASExportedCredentialData` envelope.

The actual CXF <-> Bitwarden cipher translation happens in the **Rust SDK**
(`clientService.exporters().exportCxf(...)` / `importCxf(payload:)`). The iOS layer
is responsible only for JSON encoding/decoding between Apple's `AS*` types and the
SDK's string payloads, plus driving the system credential managers.

### Platform gating

The existing CXF import/export flow is gated by `@available(iOS 26.0, *)`. The
FIDO2 extension types and the extended `Passkey` initializer are separately gated
by `@available(iOS 26.4, *)`. Below iOS 26 the import/export processors set a
failure status with the localized "not available for this device" message. A build
that references the extension types requires the iOS 26.4 SDK or newer.

### Policy gating

- Import (`ImportCXFProcessor.checkEnabled`): blocked if
  `policyService.policyAppliesToUser(.personalOwnership)`.
- Export (`ExportCXFProcessor.load`): blocked if
  `policyService.policyAppliesToUser(.disablePersonalVaultExport)`.

---

## 2. CXF import flow — file map

Entry point through repository. All paths relative to
`/Users/eminmahrt/Developer/nuri-bitwarden/ios`.

| Step | File | Role |
|------|------|------|
| System entry | `Bitwarden/Application/SceneDelegate.swift` | Detects `ASCredentialExchangeActivity` + `ASCredentialImportToken`, calls `AppProcessor.handleImportCredentials(credentialImportToken:)`. |
| Coordinator | `BitwardenShared/UI/Tools/ImportCXF/ImportCXFCoordinator.swift` | Routes `.importCredentials(token)` to `showImportCXF(...)`. |
| Route | `BitwardenShared/UI/Tools/ImportCXF/ImportCXFRoute.swift` | `.dismiss`, `.importCredentials(credentialImportToken: UUID)`. |
| UI / state | `BitwardenShared/UI/Tools/ImportCXF/ImportCXF/ImportCXFView.swift`, `ImportCXFState.swift`, `ImportCXFEffect.swift`, `ImportCXFProcessor.swift` | Drives the import screen; states `start → importing → success/failure`. |
| Repository | `BitwardenShared/Core/Tools/Repositories/ImportCiphersRepository.swift` | `DefaultImportCiphersRepository.importCiphers(credentialImportToken:onProgress:)` — the core orchestrator. |
| Service | `BitwardenShared/Core/Tools/Services/ImportCiphersService.swift` | Forwards to `ImportCiphersAPIService` to persist imported ciphers server-side. |
| API | `BitwardenShared/Core/Tools/Services/API/ImportCiphersAPIService.swift`, `API/Requests/ImportCiphersRequest.swift`, `Models/Request/ImportCiphersRequestModel.swift` | Server request to import ciphers/folders. |
| Credential manager factory | `BitwardenShared/Core/Tools/Utilities/CredentialManagerFactory.swift` | `createImportManager() -> ASCredentialImportManager`. |
| Result summary | `BitwardenShared/Core/Tools/Utilities/CXFCredentialsResult.swift`, `CXFCredentialsResultBuilder.swift` | Counts imported/exported ciphers by type for UI. |
| Tests | `BitwardenShared/Core/Tools/Repositories/ImportCiphersRepositoryTests.swift`, `UI/Tools/ImportCXF/ImportCXF/ImportCXFProcessorTests.swift`, `Core/Tools/Utilities/CXFCredentialsResultBuilderTests.swift` | Coverage. |

### Import data path (per `DefaultImportCiphersRepository.importCiphers`)

1. `credentialManagerFactory.createImportManager().importCredentials(token:)`
   → `ASExportedCredentialData`.
2. Take `credentialData.accounts.first` (else throw
   `ImportCiphersRepositoryError.noDataFound`) → the `ASImportableAccount`.
3. `JSONEncoder.cxfEncoder.encode(accountData)` → JSON string
   (else throw `.dataEncodingFailed`).
4. `clientService.exporters().importCxf(payload: accountJsonString)` →
   `[BitwardenSdk.Cipher]`. (Rust SDK performs CXF → Cipher translation.)
5. `importCiphersService.importCiphers(ciphers:folders:folderRelationships:)`
   → server import (folders and relationships are currently passed as empty).
6. `syncService.fetchSync(forceSync: true)` to refresh the vault.
7. `cxfCredentialsResultBuilder.build(from: ciphers)` → `[CXFCredentialsResult]`
   (filtered to non-empty) for the success UI.

Progress callbacks fire at `0.3` (after SDK parse), `0.8` (after server import), and
`1.0` (after sync + count).

---

## 3. CXF export flow — file map

| Step | File | Role |
|------|------|------|
| UI / state | `BitwardenShared/UI/Tools/ExportCXF/ExportCXF/ExportCXFView.swift`, `ExportCXFState.swift`, `ExportCXFAction.swift`, `ExportCXFEffect.swift`, `ExportCXFProcessor.swift` | Drives the export screen; states `start → prepared → failure`. |
| Coordinator | `BitwardenShared/UI/Tools/ExportCXF/ExportCXFCoordinator.swift`, `ExportCXFRoute.swift` | Navigation. |
| Repository | `BitwardenShared/Core/Tools/Repositories/ExportCXFCiphersRepository.swift` | `DefaultExportCXFCiphersRepository` — builds summary, fetches ciphers, calls SDK `exportCxf`, drives `ASCredentialExportManager`. |
| Vault fetch | `ExportCXFCiphersRepository.getAllCiphersToExportCXF()` → `ExportVaultService.fetchAllCiphersToExport(includeArchivedItems: false)` | Source ciphers. |
| Credential manager factory | `BitwardenShared/Core/Tools/Utilities/CredentialManagerFactory.swift` | `createExportManager(presentationAnchor:) -> ASCredentialExportManager`; `ASCredentialExportManager.exportCredentials(importableAccount:)` extension wraps the account in `ASExportedCredentialData` (formatVersion from `requestExport`, `exporterRelyingPartyIdentifier = Bundle.main.appIdentifier`, `exporterDisplayName = "Bitwarden"`, `timestamp = .now`). |
| Tests | `BitwardenShared/Core/Tools/Repositories/ExportCXFCiphersRepositoryTests.swift`, `UI/Tools/ExportCXF/ExportCXF/ExportCXFProcessorTests.swift` | Coverage. |

### Export data path (per `DefaultExportCXFCiphersRepository.getExportVaultDataForCXF`)

1. `getAllCiphersToExportCXF()` → `[Cipher]` (via `ExportVaultService`).
2. Build `BitwardenSdk.Account(id:email:name:)` from `stateService.getAccount(...)`.
3. `clientService.exporters().exportCxf(account: sdkAccount, ciphers: ciphers)`
   → serialized CXF JSON string (Rust SDK performs Cipher → CXF translation).
4. `JSONDecoder.cxfDecoder.decode(ASImportableAccount.self, from: Data(serializedCXF.utf8))`
   → `ASImportableAccount` ready for `ASCredentialExportManager`.

The summary shown on the "prepared" screen comes from
`buildCiphersToExportSummary(from:)` which calls
`cxfCredentialsResultBuilder.build(from:)` and filters out empty types.

---

## 4. CXF JSON codecs

Both directions cross the Apple <-> SDK boundary as JSON strings, so two custom
codecs are defined on `JSONEncoder`/`JSONDecoder`:

| Codec | File | Behavior |
|-------|------|----------|
| `JSONEncoder.cxfEncoder` | `BitwardenKit/Core/Platform/Services/API/Extensions/JSONEncoder+Bitwarden.swift` | `.dateEncodingStrategy = .custom { Int(date.timeIntervalSince1970) }` (epoch seconds). Used to encode `ASImportableAccount`/`ASExportedCredentialData` before passing to the SDK. |
| `JSONDecoder.cxfDecoder` | `BitwardenKit/Core/Platform/Services/API/Extensions/JSONDecoder+Bitwarden.swift` | `URLFixingJSONDecoder` with `urlArrayPropertyNames: ["urls"]`, `keyDecodingStrategy` converting snake_case/PascalCase → camelCase via `keyToCamelCase`, `.dateDecodingStrategy = .secondsSince1970`. Used to decode SDK-produced CXF JSON back into `ASImportableAccount`. |
| Tests | `BitwardenKit/Core/Platform/Services/API/Extensions/JSONEncoderBitwardenTests.swift`, `JSONDecoderBitwardenTests.swift` | Verify fractional-second / no-scheme-URL handling. |

### CXF credential types (`CXFCredentialsResult.CXFCredentialType`)

Defined in `BitwardenShared/Core/Tools/Utilities/CXFCredentialsResult.swift`:

| `CXFCredentialType` | Cipher detection (in `DefaultCXFCredentialsResultBuilder.build`) |
|---------------------|-------------------------------------------------------------------|
| `.password` | `type == .login && login?.fido2Credentials?.isEmpty != false` (login with no FIDO2 creds) |
| `.passkey` | `type == .login && login?.fido2Credentials?.isEmpty == false` (login with FIDO2 creds) |
| `.card` | `type == .card` |
| `.identity` | `type == .identity` |
| `.secureNote` | `type == .secureNote` |
| `.sshKey` | `type == .sshKey` |

### `ASImportableCredential` variants (from `ASImportableAccount+Extensions.dump`)

The `ASImportableItem.credentials` array contains `ASImportableCredential` enum
cases. The dump helper in
`BitwardenShared/Core/Vault/Services/TestHelpers/ASImportableAccount+Extensions.swift`
enumerates:

- `.basicAuthentication(BasicAuthentication)` — `userName`, `password` (each with
  `fieldType` + `value`).
- `.passkey(Passkey)` — `credentialID`, `key`, `relyingPartyIdentifier`,
  `userDisplayName`, `userName`, `userHandle`, and, on iOS 26.4+,
  optional `fido2Extensions`.
- `.totp(TOTP)` — `algorithm`, `digits`, `issuer?`, `period`, `secret`, `userName?`.
- `.note(Note)` — `content`.
- `.creditCard(CreditCard)` — `fullName?`, `number?`, `cardType?`, `expiryDate?`,
  `validFrom?`, `verificationNumber?` (each optional, with `.value`).
- `@unknown default` — logged as "unknown default".

### CXF fixtures

`BitwardenShared/Core/Vault/Services/Fixtures/cxfTwoBasicAuthCiphers.json` — two
login items (GitHub, Google) with `basic-auth` credentials. Dates are epoch seconds
(e.g. `1732226366`). Loaded via `CXFFixtures.twoBasicAuthCiphers`.

`BitwardenShared/Core/Vault/Services/TestHelpers/CXFPasskeyPRF+Fixtures.swift`
contains only deterministic synthetic passkeys for the valid, missing-PRF,
malformed-seed, duplicate, and unsupported-signing-key cases. The fixture tests
encode and decode every case through Apple's AuthenticationServices `Codable`
types. They do not exercise the production import mapping owned by issue #27.

---

## 5. WebAuthn / FIDO2 extensions (PRF + hmac-secret)

The iOS app surfaces FIDO2/WebAuthn extension data in four areas: (a) Apple
Credential Exchange passkey types, (b) server-facing domain structs, (c) Bitwarden
SDK types passed to the FIDO2 authenticator, and (d) Apple `ASPasskey*` assertion
types.

### 5.1 PRF — Apple Credential Exchange types (iOS 26.4+)

Apple's current CXF model is:

```swift
ASImportableCredential.Passkey(
    credentialID: Data,
    relyingPartyIdentifier: String,
    userName: String,
    userDisplayName: String,
    userHandle: Data,
    key: Data,
    fido2Extensions: ASImportableFIDO2Extensions?
)

ASImportableFIDO2Extensions(
    hmacCredentials: ASImportableFIDO2HMACCredential?,
    largeBlob: ASImportableFIDO2LargeBlob?
)

ASImportableFIDO2HMACCredential(
    algorithm: .sha256,
    credentialWithUV: Data,
    credentialWithoutUV: Data
)
```

The corresponding CXF members are `fido2Extensions.hmacCredentials.algorithm`
(`hmac-sha256`), `credWithUV`, and `credWithoutUV`. Both credentials are raw
32-byte HMAC seed state and are base64url-encoded only by the `Codable` boundary.
They are not evaluated WebAuthn PRF outputs. `hmacCredentials` and the entire
`fido2Extensions` object are optional; the two credential buffers are required
when `hmacCredentials` is present.

The passkey `key` remains PKCS#8 DER. AuthenticationServices transports its bytes
but the shared importer must derive and validate the signing algorithm rather than
assuming ES256. `largeBlob` exists in the Apple model but is not required by the
first Nuri proof.

Official references:

- <https://developer.apple.com/documentation/authenticationservices/asimportablecredential/passkey>
- <https://developer.apple.com/documentation/authenticationservices/asimportablefido2extensions>
- <https://developer.apple.com/documentation/authenticationservices/asimportablefido2hmaccredential>

### 5.2 PRF — server-facing domain structs (`WebAuthnAuthentication*`)

All under `BitwardenShared/Core/Auth/Domain/`:

| Struct | File | Maps to WebAuthn spec |
|--------|------|------------------------|
| `WebAuthnAuthenticationExtensionsClientInputs` | `WebAuthnAuthenticationExtensionsClientInputs.swift` | `AuthenticationExtensionsClientInputs` — wraps a single `prf` field. |
| `WebAuthnAuthenticationExtensionsPRFInputs` | `WebAuthnAuthenticationExtensionsPRFInputs.swift` | `AuthenticationExtensionsPRFInputs` — `eval: WebAuthnAuthenticationExtensionsPRFValues?`, `evalByCredential: [String: WebAuthnAuthenticationExtensionsPRFValues]?`. |
| `WebAuthnAuthenticationExtensionsPRFValues` | `WebAuthnAuthenticationExtensionsPRFValues.swift` | `AuthenticationExtensionsPRFValues` — `first: String`, `second: String?` (base64url salts). |
| `WebAuthnPublicKeyCredentialCreationOptions` | `WebAuthnPublicKeyCredentialCreationOptions.swift` | `PublicKeyCredentialCreationOptions` — `extensions: WebAuthnAuthenticationExtensionsClientInputs?` (PRF on registration). |
| `WebAuthnPublicKeyCredentialRequestOptions` | `WebAuthnPublicKeyCredentialRequestOptions.swift` | `PublicKeyCredentialRequestOptions` — `extensions: WebAuthnAuthenticationExtensionsClientInputs?` (PRF on assertion). |
| `WebAuthnPublicKeyCredentialWithAttestationResponse` | `WebAuthnPublicKeyCredentialWithAttestationResponse.swift` | `PublicKeyCredential` — `id`, `rawId`, `response`, `type`. **Note:** `clientExtensionsResults` is intentionally omitted (comment: "We are currently not sending back any extension results to the server"). |
| `WebAuthnAuthenticatorAttestationResponse` | `WebAuthnAuthenticatorAttestationResponse.swift` | `AuthenticatorAttestationResponse` — `attestationObject`, `clientDataJSON`. |

These structs are `Codable, Equatable, Hashable, Sendable` and mirror the W3C
WebAuthn Level 3 dictionary shapes, referenced by spec links in each doc comment.

### 5.3 PRF — SDK types (BitwardenSdk, Rust-backed)

Used by the autofill/credential services and the auth fixtures. These come from
the `BitwardenSdk` package (Rust FFI) and are referenced throughout:

- `MakeCredentialExtensionsInput(prf: MakeCredentialPrfInput?)` — registration
  extension input. `MakeCredentialPrfInput(eval: PrfInputValues?)`.
  `PrfInputValues(first: Data, second: Data?)`.
- `MakeCredentialExtensionsOutput(prf: MakeCredentialPrfOutput?)` —
  `MakeCredentialPrfOutput(enabled: Bool, results: PrfOutputValues?)`.
  `PrfOutputValues(first: Data, second: Data?)`.
- `GetAssertionExtensionsOutput(prf: GetAssertionPrfOutput?)` — assertion
  extension output. `GetAssertionPrfOutput(results: PrfOutputValues?)`.

Fixture defaults live in:
- `BitwardenShared/Core/Auth/Services/TestHelpers/BitwardenSdk+AuthFixtures.swift`
  (lines 59, 95): `GetAssertionExtensionsOutput = .init(prf: nil)`,
  `MakeCredentialExtensionsOutput = .init(prf: nil)`.
- `AuthenticatorShared/Core/Auth/Services/TestHelpers/BitwardenSdk+AuthFixtures.swift`
  (lines 59, 77): identical defaults for the Authenticator target.

### 5.4 PRF — Apple bridging (`ASPasskeyAssertionCredential`)

`BitwardenShared/Core/Autofill/Extensions/BitwardenSdk+Autofill.swift`:

- `ASPasskeyAssertionCredential(assertionResult:rpId:clientDataHash:)` — on iOS 18+
  passes `extensionOutput: nil` with the comment:
  `// TODO: PM-26177 once SDK is updated for full PRF support we can include this`.
  The `GetAssertionRequest` initializers in the same file hardcode
  `extensions: nil`, so PRF client inputs are **not currently forwarded** from the
  Apple request into the SDK's `GetAssertionRequest`.
- `MakeCredentialRequest.debugDescription` and `MakeCredentialResult.debugDescription`
  include the SDK `extensions` field in their debug dumps.

Tests that confirm the current "nil extension" state:
- `AutofillCredentialServiceTests.swift:743` —
  `extensions: GetAssertionExtensionsOutput(prf: nil)` on the SDK result, then
  `XCTAssertNil(result.extensionOutput)` at the Apple-bridging boundary (with the
  same PM-26177 TODO).
- `BitwardenSdkAutofillTests.swift` (lines 132-189) — fixture round-trips of
  `MakeCredentialPrfInput`/`MakeCredentialPrfOutput` through the SDK, asserting the
  `Extensions` field carries `prf` on both input and output.

### 5.5 PRF — server save-credential model

`BitwardenShared/Core/Auth/Models/Request/WebAuthnLoginSaveCredentialRequestModel.swift`:

- `supportsPrf: Bool` — "true if the credential was created with PRF support."
- `deviceResponse: WebAuthnPublicKeyCredentialWithAttestationResponse` — the
  attestation response sent back to the server (extension results omitted, see 5.2).

Tested in
`BitwardenShared/Core/Auth/Services/API/Auth/Requests/WebAuthnLoginSaveCredentialRequestTests.swift`
(`supportsPrf: true/false`) and in
`BitwardenShared/Core/Auth/Services/API/Auth/AuthAPIServiceTests.swift` which
asserts the `options.extensions?.prf?.eval?.first` / `.second` / `evalByCredential`
paths round-trip through the assertion/creation option responses (fixtures in
`BitwardenShared/Core/Auth/Services/API/Auth/Fixtures/WebAuthnLoginCredentialAssertionOptions.json`
and `...CreationOptions.json`).

### 5.6 Device-auth-key `hmac-secret`

Separate from CXF's iOS 26.4 `ASImportableFIDO2HMACCredential`, an encrypted
device-auth-key HMAC secret is referenced in this domain model:

- `BitwardenShared/Core/Auth/Models/Domain/DeviceAuthKeyKeychainRecord.swift`
  — `public let hmacSecret: EncString?` with doc:
  "The HMAC secret, if the credential supports the hmac-secret extension."
- Fixtures: `DeviceAuthKeyKeychainRecord+Fixtures.swift` —
  `hmacSecret: EncString? = "encrypted-hmac-secret"`.

This record is the on-device keychain payload for the **device auth key** (the
"unlock passkey" feature, PM-26177). The `DeviceAuthKeyService`
(`BitwardenShared/Core/Auth/Services/DeviceAuthKeyService.swift`) is the service
surface, but its `createDeviceAuthKey` and `assertDeviceAuthKey` are currently
**stubs** that throw `DeviceAuthKeyError.notImplemented` (both annotated
`// TODO: PM-26177 to finish building out this stub`). The `hmacSecret` field is
modeled but not yet populated by any live flow.

---

## 6. Where passkey import/export crosses CXF

The CXF and passkey/FIDO2 stacks intersect in two places:

1. **CXF credential type detection** —
   `DefaultCXFCredentialsResultBuilder.build(from:)` classifies a login cipher as
   `.passkey` iff `login?.fido2Credentials?.isEmpty == false`. This is purely a
   UI-summary distinction; the actual FIDO2 credential data round-trips through the
   SDK's CXF (de)serialization, not through Apple's `ASPasskey*` types.
2. **`ASImportableCredential.passkey`** — on iOS 26.4+, Apple's decoded passkey
   carries optional `fido2Extensions.hmacCredentials`. The existing iOS import
   repository encodes the `ASImportableAccount` with `JSONEncoder.cxfEncoder`, so
   the Apple fields reach the serialized CXF payload handed to
   `clientService.exporters().importCxf(payload:)`. The shared SDK must then
   validate and preserve them; that production path remains issue #27 and is not
   implemented by the issue #28 fixtures.

The same distinction applies in reverse: Apple's types can represent the data,
but the SDK exporter must emit it before the iOS export repository can decode it.
General export is parked until after the first device proof.

---

## 7. Negative cases and secret-safe diagnostics

The iOS fixture surface freezes these transport inputs:

| Case | Apple type behavior | Downstream requirement |
|---|---|---|
| Valid | Decodes one passkey with `.sha256` and two 32-byte seeds | Preserve both seeds exactly. |
| Missing PRF | Decodes with `fido2Extensions == nil` | Authentication may remain possible; PRF-required wallet recovery must fail closed. |
| Malformed seed | Decodes a 31-byte `credentialWithUV` buffer | Import validation must reject it before persistence. |
| Duplicate | Decodes two passkeys with the same credential ID | Import policy must detect the duplicate without logging the ID. |
| Unsupported key | Decodes a valid Ed25519 PKCS#8 key as opaque `Data` | The ES256 MVP must reject it instead of relabeling it. |

Test matchers may report field names, presence, byte lengths, and a generic
match/mismatch result. They must never interpolate a private PKCS#8 key, UV or
non-UV HMAC seed, evaluated PRF output, or a real credential payload. The shared
`ASImportableAccount.dump()` helper therefore prints only redaction markers and
lengths for passkey private keys and HMAC credentials.

---

## 8. Open work / TODOs

| Ticket | Location | Status |
|--------|----------|--------|
| #27 | CXF import repository / SDK handoff | Validate and preserve iOS 26.4 FIDO2 extension state in production. |
| PM-26177 | `DeviceAuthKeyService.createDeviceAuthKey` / `assertDeviceAuthKey` | Stub throws `.notImplemented`. |
| PM-26177 | `ASPasskeyAssertionCredential(...).init` `extensionOutput: nil` | PRF output not forwarded to Apple on assertion. |
| PM-26177 | `GetAssertionRequest.init(...)` `extensions: nil` | PRF client inputs not forwarded from Apple request to SDK. |
| PM-26177 | `BitwardenSdk+Autofill.swift:80` `extensionOutput: nil` | Same TODO marker in the autofill extension. |

The unifying thread is PM-26177: full PRF support for the device auth key
("unlock passkey") flow. Until that lands, PRF is modeled end-to-end (server domain
structs, SDK types, fixtures, request models, test fixtures) but the live Apple
bridging path intentionally drops extension input/output at the boundaries.

---

## 9. Key file index (absolute paths)

CXF:
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/Bitwarden/Application/SceneDelegate.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/UI/Tools/ImportCXF/ImportCXFCoordinator.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/UI/Tools/ImportCXF/ImportCXFRoute.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/UI/Tools/ImportCXF/ImportCXF/ImportCXFProcessor.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/UI/Tools/ImportCXF/ImportCXF/ImportCXFState.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/UI/Tools/ImportCXF/ImportCXF/ImportCXFEffect.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/UI/Tools/ExportCXF/ExportCXF/ExportCXFProcessor.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/UI/Tools/ExportCXF/ExportCXF/ExportCXFState.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Tools/Repositories/ImportCiphersRepository.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Tools/Repositories/ExportCXFCiphersRepository.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Tools/Services/ImportCiphersService.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Tools/Utilities/CredentialManagerFactory.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Tools/Utilities/CXFCredentialsResult.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Tools/Utilities/CXFCredentialsResultBuilder.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Vault/Services/Fixtures/CXF+Fixtures.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Vault/Services/Fixtures/cxfTwoBasicAuthCiphers.json`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Vault/Services/TestHelpers/ASImportableItem+Extensions.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Vault/Services/TestHelpers/ASImportableAccount+Extensions.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Vault/Services/TestHelpers/CXFPasskeyPRF+Fixtures.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Vault/Services/CXFPasskeyPRFFixturesTests.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenKit/Core/Platform/Services/API/Extensions/JSONEncoder+Bitwarden.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenKit/Core/Platform/Services/API/Extensions/JSONDecoder+Bitwarden.swift`

WebAuthn / PRF:
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Domain/WebAuthnAuthenticationExtensionsClientInputs.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Domain/WebAuthnAuthenticationExtensionsPRFInputs.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Domain/WebAuthnAuthenticationExtensionsPRFValues.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Domain/WebAuthnPublicKeyCredentialCreationOptions.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Domain/WebAuthnPublicKeyCredentialRequestOptions.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Domain/WebAuthnPublicKeyCredentialWithAttestationResponse.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Domain/WebAuthnAuthenticatorAttestationResponse.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Models/Request/WebAuthnLoginSaveCredentialRequestModel.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Autofill/Extensions/BitwardenSdk+Autofill.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Services/TestHelpers/BitwardenSdk+AuthFixtures.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Services/API/Auth/Fixtures/WebAuthnLoginCredentialAssertionOptions.json`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Services/API/Auth/Fixtures/WebAuthnLoginCredentialCreationOptions.json`

hmac-secret / device auth key:
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Models/Domain/DeviceAuthKeyKeychainRecord.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Models/Domain/Fixtures/DeviceAuthKeyKeychainRecord+Fixtures.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Auth/Services/DeviceAuthKeyService.swift`

FIDO2 credential store (passkey autofill/create):
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Vault/Services/Fido2CredentialStoreService.swift`
- `/Users/eminmahrt/Developer/nuri-bitwarden/ios/BitwardenShared/Core/Autofill/Services/AutofillCredentialService.swift`
