//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import VirgilSDK
import VirgilCrypto

// MARK: - Extension with deprecated operations
public extension EThree {
    /// Initializes EThree with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify about changes of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    @available(*, deprecated, message: "Use constructor instead")
    static func initialize(tokenCallback: @escaping RenewJwtCallback,
                           changedKeyDelegate: ChangedKeyDelegate? = nil,
                           storageParams: KeychainStorageParams? = nil) -> GenericOperation<EThree> {
        return CallbackOperation { _, completion in
            do {
                let accessTokenProvider = CachingJwtProvider { tokenCallback($1) }

                let tokenContext = TokenContext(service: "cards", operation: "")

                let getTokenOperation = CallbackOperation<AccessToken> { _, completion in
                    accessTokenProvider.getToken(with: tokenContext, completion: completion)
                }

                let token = try getTokenOperation.startSync().get()

                let ethree = try EThree(identity: token.identity(),
                                        accessTokenProvider: accessTokenProvider,
                                        changedKeyDelegate: changedKeyDelegate,
                                        storageParams: storageParams,
                                        enableRatchet: Defaults.enableRatchet,
                                        keyRotationInterval: Defaults.keyRotationInterval)

                completion(ethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Retrieves users public keys from the Virgil Cloud
    ///
    /// - Parameter identities: array of identities to find
    /// - Returns: CallbackOperation<LookupResult>
    @available(*, deprecated, message: "Use findUsers instead.")
    func lookupPublicKeys(of identities: [String]) -> GenericOperation<LookupResult> {
        return CallbackOperation { _, completion in
            do {
                let cards = try self.findUsers(with: identities, forceReload: true).startSync().get()

                let result = cards.mapValues { $0.publicKey }

                completion(result, nil)
            }
            catch {
                completion(nil, error)
            }

        }
    }

    /// Signs then encrypts data for group of users
    ///
    /// - Parameters:
    ///   - data: data to encrypt
    ///   - recipientKeys: result of lookupPublicKeys call recipient PublicKeys to sign and encrypt with
    /// - Returns: decrypted Data
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @available(*, deprecated, message: "Use encryptForUsers method instead.")
    @objc func encrypt(data: Data, for recipientKeys: LookupResult) throws -> Data {
        return try self.encryptInternal(data: data, for: self.lookupResultToPublicKeys(recipientKeys))
    }

    /// Decrypts and verifies data from users
    ///
    /// - Parameters:
    ///   - data: data to decrypt
    ///   - senderPublicKey: sender PublicKey to verify with
    /// - Returns: decrypted Data
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @available(*, deprecated, message: "Use decryptFromUser method instead.")
    @objc func decrypt(data: Data, from senderPublicKey: VirgilPublicKey) throws -> Data {
        return try self.decryptInternal(data: data, from: senderPublicKey)
    }

    /// Encrypts data stream
    ///
    /// - Parameters:
    ///   - stream: data stream to be encrypted
    ///   - outputStream: stream with encrypted data
    ///   - recipientKeys: result of lookupPublicKeys call recipient PublicKeys to sign and encrypt with.
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @available(*, deprecated, message: "Use encryptForUsers method instead.")
    @objc func encrypt(_ stream: InputStream, to outputStream: OutputStream,
                       for recipientKeys: LookupResult) throws {
        try self.encryptInternal(stream, to: outputStream, for: self.lookupResultToPublicKeys(recipientKeys))
    }

    /// Signs then encrypts string for group of users
    ///
    /// - Parameters:
    ///   - text: String to encrypt
    ///   - recipientKeys: result of lookupPublicKeys call recipient PublicKeys to sign and encrypt with.
    /// - Returns: encrypted base64String
    /// - Throws: corresponding error
    /// - Important: Automatically includes self key to recipientsKeys.
    /// - Important: Requires private key in local storage
    /// - Note: Avoid key duplication
    @available(*, deprecated, message: "Use encryptForUsers method instead.")
    @objc func encrypt(text: String, for recipientKeys: LookupResult) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }

        return try self.encryptInternal(data: data,
                                        for: self.lookupResultToPublicKeys(recipientKeys))
            .base64EncodedString()
    }

    /// Decrypts and verifies base64 string from users
    ///
    /// - Parameters:
    ///   - text: encrypted String
    ///   - senderPublicKey: sender PublicKey to verify with
    /// - Returns: decrypted String
    /// - Throws: corresponding error
    /// - Important: Requires private key in local storage
    @available(*, deprecated, message: "Use decryptFromUser method instead.")
    @objc func decrypt(text: String, from senderPublicKey: VirgilPublicKey) throws -> String {
        guard let data = Data(base64Encoded: text) else {
            throw EThreeError.strToDataFailed
        }

        let decryptedData = try self.decryptInternal(data: data, from: senderPublicKey)

        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }
}

public extension EThree {
    /// Initializes E3Kit with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify changing of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    ///   - completion: completion handler
    ///   - ethree: initialized EThree instance
    ///   - error: corresponding error
    @available(*, deprecated, message: "Use constructor instead")
    @objc static func initialize(tokenCallback: @escaping RenewJwtCallback,
                                 changedKeyDelegate: ChangedKeyDelegate? = nil,
                                 storageParams: KeychainStorageParams? = nil,
                                 completion: @escaping (_ ethree: EThree?, _ error: Error?) -> Void) {
        EThree.initialize(tokenCallback: tokenCallback,
                          changedKeyDelegate: changedKeyDelegate,
                          storageParams: storageParams)
            .start(completion: completion)
    }

    /// Retrieves users public keys from the Virgil Cloud
    ///
    /// - Parameters:
    ///   - identities: array of identities to find
    ///   - completion: completion handler
    ///   - lookupResult: dictionary with idenities as keys and found keys as values
    ///   - error: corresponding error
    @available(*, deprecated, message: "Use findUsers instead.")
    @objc func lookupPublicKeys(of identities: [String],
                                completion: @escaping (_ lookupResult: LookupResult?,
                                                       _ error: Error?) -> Void) {
        self.lookupPublicKeys(of: identities).start(completion: completion)
    }
}
