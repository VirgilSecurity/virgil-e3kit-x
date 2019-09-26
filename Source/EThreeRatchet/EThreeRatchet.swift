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
import VirgilSDKRatchet

/// Class containing key management features and Double Ratchet encryption
@objc(VTEEThreeRatchet) open class EThreeRatchet: EThreeBase {
    private var secureChat: SecureChat?
    private var timer: RepeatingTimer?

    /// Time Interval, which defines how often keys will be rotated
    @objc public let keyRotationInterval: TimeInterval

    /// Initializes EThreeRatchet
    ///
    /// - Parameters:
    ///   - identity: identity of user
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify changing of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    ///   - keyRotationInterval: Time Interval, which defines how often keys will be rotated
    public static func initialize(identity: String,
                                  tokenCallback: @escaping RenewJwtCallback,
                                  changedKeyDelegate: ChangedKeyDelegate? = nil,
                                  storageParams: KeychainStorageParams? = nil,
                                  keyRotationInterval: TimeInterval = 3_600) -> GenericOperation<EThreeRatchet> {
        return CallbackOperation { _, completion in
            do {
                let ethree = try EThree(identity: identity,
                                        tokenCallback: tokenCallback,
                                        changedKeyDelegate: changedKeyDelegate,
                                        storageParams: storageParams)

                let rethree = try EThreeRatchet.initialize(ethree: ethree,
                                                           keyRotationInterval: keyRotationInterval)
                    .startSync()
                    .get()

                completion(rethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Initializes EThreeRatchet
    ///
    /// - Parameters:
    ///   - ethree: `EThree` instance
    ///   - keyRotationInterval: Time Interval, which defines how often keys will be rotated
    public static func initialize(ethree: EThree,
                                  keyRotationInterval: TimeInterval = 3_600) -> GenericOperation<EThreeRatchet> {
        return CallbackOperation { _, completion in
            do {
                let rethree = try EThreeRatchet(ethree: ethree, keyRotationInterval: keyRotationInterval)

                if try rethree.localKeyStorage.exists() {
                    try rethree.setupSecureChat()
                }

                completion(rethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    internal init(ethree: EThreeBase, keyRotationInterval: TimeInterval) throws {
        self.keyRotationInterval = keyRotationInterval

        try super.init(identity: ethree.identity,
                       cardManager: ethree.cardManager,
                       accessTokenProvider: ethree.accessTokenProvider,
                       localKeyStorage: ethree.localKeyStorage,
                       cloudKeyManager: ethree.cloudKeyManager,
                       lookupManager: ethree.lookupManager)
    }

    private func setupSecureChat(newCard: Card? = nil) throws {
        let selfCard = try newCard ?? self.lookupManager.lookupCard(of: self.identity, forceReload: true)
        let keyPair = try self.localKeyStorage.retrieveKeyPair()

        let context = SecureChatContext(identityCard: selfCard,
                                        identityPrivateKey: keyPair.privateKey,
                                        accessTokenProvider: self.accessTokenProvider)

        let chat = try SecureChat(context: context)

        // If user rotated Card new chat should reset all keys
        if newCard != nil {
            do {
                try chat.reset().startSync().get()
            }
            catch let error as NSError where error.code == 50017 {} // When there's no keys on cloud. Should be fixed on server side.
        }

        Log.debug("Key rotation started")
        let logs = try chat.rotateKeys().startSync().get()
        Log.debug("Key rotation succeed: \(logs.description)")

        self.scheduleKeyRotation(with: chat)

        self.secureChat = chat
    }

    private func scheduleKeyRotation(with chat: SecureChat) {
        self.timer = RepeatingTimer(interval: self.keyRotationInterval) {
            Log.debug("Key rotation started")
            do {
                let logs = try chat.rotateKeys().startSync().get()
                Log.debug("Key rotation succeed: \(logs.description)")
            } catch {
                Log.error("Key rotation failed: \(error.localizedDescription)")
            }
        }

        self.timer?.resume()
    }

    internal func getSecureChat() throws -> SecureChat {
        guard let secureChat = self.secureChat else {
            throw EThreeError.missingPrivateKey
        }

        return secureChat
    }
}

extension EThreeRatchet {
    override internal func privateKeyChanged(newCard: Card? = nil) throws {
        try super.privateKeyChanged()

        try self.setupSecureChat(newCard: newCard)
    }

    override internal func privateKeyDeleted() throws {
        try super.privateKeyDeleted()

        self.secureChat = nil
        self.timer = nil
    }
}
