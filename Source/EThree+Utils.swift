//
// Copyright (C) 2015-2020 Virgil Security Inc.
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
import VirgilSDKRatchet

extension EThree {
    internal struct PrivateKeyChangedParams {
        internal let card: Card
        internal let isNew: Bool
    }

    internal func privateKeyChanged(params: PrivateKeyChangedParams? = nil) throws {
        if let params = params {
            try self.lookupManager.cardStorage.storeCard(params.card)
        }

        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        try self.setupGroupManager(keyPair: selfKeyPair)
        try self.setupTempChannelManager(keyPair: selfKeyPair)

        if self.enableRatchet {
            try self.setupRatchet(params: params, keyPair: selfKeyPair)
        }
    }

    internal func privateKeyDeleted() throws {
        try self.lookupManager.cardStorage.reset()
        try self.groupManager?.localGroupStorage.reset()
        try self.tempChannelManager?.localStorage.reset()

        self.groupManager = nil
        self.tempChannelManager = nil
        self.secureChat = nil
        self.timer = nil
    }

    internal func computeSessionId(from identifier: Data) throws -> Data {
        guard identifier.count > 10 else {
            throw GroupError.shortGroupId
        }

        return self.crypto.computeHash(for: identifier, using: .sha512).subdata(in: 0..<32)
    }

    internal static func getConnection() -> HttpConnection {
        let virgilAdapter = VirgilAgentAdapter(product: ProductInfo.name,
                                               version: ProductInfo.version)

        return HttpConnection(adapters: [virgilAdapter])
    }

    internal func publishCardThenSaveLocal(keyPair: VirgilKeyPair? = nil,
                                           publishCardCallback: PublishCardCallback? = nil,
                                           previousCardId: String? = nil) throws {
        let keyPair = try keyPair ?? self.crypto.generateKeyPair(ofType: self.keyPairType)

        let card: Card

        if let publishCardCallback = publishCardCallback {
            let modelSigner = ModelSigner(crypto: self.crypto)

            let rawCard = try CardManager.generateRawCard(crypto: self.crypto,
                                                          modelSigner: modelSigner,
                                                          privateKey: keyPair.privateKey,
                                                          publicKey: keyPair.publicKey,
                                                          identity: self.identity)

            card = try publishCardCallback(rawCard)
        }
        else {
            card = try self.cardManager.publishCard(privateKey: keyPair.privateKey,
                                                    publicKey: keyPair.publicKey,
                                                    identity: self.identity,
                                                    previousCardId: previousCardId)
            .startSync()
            .get()
        }

        let data = try self.crypto.exportPrivateKey(keyPair.privateKey)

        try self.localKeyStorage.store(data: data)

        let params = PrivateKeyChangedParams(card: card, isNew: true)
        try self.privateKeyChanged(params: params)
    }

    private func setupTempChannelManager(keyPair: VirgilKeyPair) throws {
        self.tempChannelManager = try TempChannelManager(appGroup: self.appGroup,
                                                         crypto: self.crypto,
                                                         accessTokenProvider: self.accessTokenProvider,
                                                         localKeyStorage: self.localKeyStorage,
                                                         keyknoxServiceUrl: self.serviceUrls.keyknoxServiceUrl,
                                                         lookupManager: self.lookupManager,
                                                         keyPairType: self.keyPairType,
                                                         keyPair: keyPair)
    }

    private func setupGroupManager(keyPair: VirgilKeyPair) throws {
        let localGroupStorage = try FileGroupStorage(appGroup: self.appGroup,
                                                     identity: self.identity,
                                                     crypto: self.crypto,
                                                     identityKeyPair: keyPair)

        let cloudTicketStorage = try CloudTicketStorage(accessTokenProvider: self.accessTokenProvider,
                                                        localKeyStorage: self.localKeyStorage,
                                                        keyknoxServiceUrl: self.serviceUrls.keyknoxServiceUrl)

         self.groupManager = GroupManager(localGroupStorage: localGroupStorage,
                                          cloudTicketStorage: cloudTicketStorage,
                                          localKeyStorage: self.localKeyStorage,
                                          lookupManager: self.lookupManager,
                                          crypto: self.crypto)
     }

    internal func getGroupManager() throws -> GroupManager {
        guard let manager = self.groupManager else {
            throw EThreeError.missingPrivateKey
        }

        return manager
    }

    internal func getTempChannelManager() throws -> TempChannelManager {
        guard let manager = self.tempChannelManager else {
            throw EThreeError.missingPrivateKey
        }

        return manager
    }
}

extension EThree {
    private func setupRatchet(params: PrivateKeyChangedParams? = nil, keyPair: VirgilKeyPair) throws {
        guard self.enableRatchet else {
            throw EThreeRatchetError.ratchetIsDisabled
        }

        if let params = params {
            let chat = try self.setupSecureChat(keyPair: keyPair, card: params.card)

            if params.isNew {
                do {
                    try chat.reset().startSync().get()
                } // When there's no keys on cloud. Should be fixed on server side.
                catch let error as ServiceError where error.errorCode == ServiceErrorCodes.noKeyDataForUser.rawValue {}

                try self.cloudRatchetStorage.reset()
            }

            Log.debug("Key rotation started")
            let logs = try chat.rotateKeys().startSync().get()
            Log.debug("Key rotation succeed: \(logs.description)")

            try self.scheduleKeysRotation(with: chat, startFromNow: false)
        } else {
            guard let card = self.findCachedUser(with: self.identity) else {
                throw EThreeRatchetError.noSelfCardLocally
            }

            let chat = try self.setupSecureChat(keyPair: keyPair, card: card)

            try self.scheduleKeysRotation(with: chat, startFromNow: !self.offlineInit)
        }
    }

    private func setupSecureChat(keyPair: VirgilKeyPair, card: Card) throws -> SecureChat {
        let context = SecureChatContext(identityCard: card,
                                        identityPrivateKey: keyPair.privateKey,
                                        accessTokenProvider: self.accessTokenProvider,
                                        enablePostQuantum: self.enableRatchetPqc)
        context.appName = self.appName
        context.appGroup = self.appGroup

        context.client = RatchetClient(accessTokenProvider: self.accessTokenProvider,
                                       serviceUrl: self.serviceUrls.ratchetServiceUrl,
                                       connection: EThree.getConnection(),
                                       retryConfig: ExpBackoffRetry.Config())

        let chat = try SecureChat(context: context)
        self.secureChat = chat

        return chat
    }

    private func scheduleKeysRotation(with chat: SecureChat, startFromNow: Bool) throws {
        let chat = try self.getSecureChat()

        self.timer = RepeatingTimer(interval: self.keyRotationInterval, startFromNow: startFromNow) {
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
        guard self.enableRatchet else {
            throw EThreeRatchetError.ratchetIsDisabled
        }

        guard let secureChat = self.secureChat else {
            throw EThreeError.missingPrivateKey
        }

        return secureChat
    }

    internal func startRatchetSessionAsSender(secureChat: SecureChat,
                                              receiverCard card: Card,
                                              name: String?) throws -> SecureSession {
        do {
            return try secureChat.startNewSessionAsSender(receiverCard: card, name: name, enablePostQuantum: self.enableRatchetPqc)
                .startSync()
                .get()
        }
        catch let error as ServiceError where error.errorCode == ServiceErrorCodes.noKeyDataForUser.rawValue {
            throw EThreeRatchetError.userIsNotUsingRatchet
        }
    }
}
