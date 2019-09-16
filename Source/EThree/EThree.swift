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

/// Main class containing all features of E3Kit
@objc(VTEEThree) open class EThree: EThreeBase {
    internal var groupManager: GroupManager?

    internal func getGroupManager() throws -> GroupManager {
        guard let manager = self.groupManager else {
            throw EThreeError.missingPrivateKey
        }

        return manager
    }

    /// Initializes E3Kit with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify about changes of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    @available(*, deprecated, message: "Use constructor instead")
    public static func initialize(tokenCallback: @escaping RenewJwtCallback,
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
                                        storageParams: storageParams)

                completion(ethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Initializer
    ///
    /// - Parameters:
    ///   - identity: User identity
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify about changes of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    /// - Throws: corresponding error
    /// - Important: identity should be the same as in JWT generated at server side
    @objc public convenience init(identity: String,
                                  tokenCallback: @escaping RenewJwtCallback,
                                  changedKeyDelegate: ChangedKeyDelegate? = nil,
                                  storageParams: KeychainStorageParams? = nil) throws {
        let accessTokenProvider = CachingJwtProvider { tokenCallback($1) }

        try self.init(identity: identity,
                      accessTokenProvider: accessTokenProvider,
                      changedKeyDelegate: changedKeyDelegate,
                      storageParams: storageParams)
    }

    internal override func privateKeyChanged(newCard: Card? = nil) throws {
        try super.privateKeyChanged(newCard: newCard)

        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let localGroupStorage = try FileGroupStorage(identity: self.identity,
                                                     crypto: self.crypto,
                                                     identityKeyPair: selfKeyPair)
        let cloudTicketStorage = try CloudTicketStorage(accessTokenProvider: self.accessTokenProvider,
                                                        localKeyStorage: self.localKeyStorage)
        self.groupManager = GroupManager(localGroupStorage: localGroupStorage,
                                         cloudTicketStorage: cloudTicketStorage,
                                         localKeyStorage: self.localKeyStorage,
                                         lookupManager: self.lookupManager,
                                         crypto: self.crypto)
    }

    internal override func privateKeyDeleted() throws {
        try super.privateKeyDeleted()
        
        try self.groupManager?.localGroupStorage.reset()
        self.groupManager = nil
    }

}
