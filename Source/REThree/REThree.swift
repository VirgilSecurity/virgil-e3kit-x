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
import VirgilSDKRatchet

@objc(VTEREThree) open class REThree: EThreeBase {
    @objc public private(set) var secureChat: SecureChat?

    // TODO: Add initializers

    public static func initialize(ethreeBase: EThreeBase) -> GenericOperation<REThree> {
        return CallbackOperation { _, completion in
            do {
                let rethree = try REThree(ethreeBase: ethreeBase)

                if try rethree.localKeyStorage.exists() {
                    try rethree.setupSecureChat()
                }

                completion(rethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    internal init(ethreeBase: EThreeBase) throws {
        try super.init(identity: ethreeBase.identity,
                       cardManager: ethreeBase.cardManager,
                       accessTokenProvider: ethreeBase.accessTokenProvider,
                       localKeyStorage: ethreeBase.localKeyStorage,
                       cloudKeyManager: ethreeBase.cloudKeyManager,
                       lookupManager: ethreeBase.lookupManager)
    }

    private func setupSecureChat() throws {
        let selfCard = try self.lookupManager.lookupCard(of: self.identity)
        let keyPair = try self.localKeyStorage.retrieveKeyPair()

        let context = SecureChatContext(identityCard: selfCard,
                                        identityPrivateKey: keyPair.privateKey,
                                        accessTokenProvider: self.accessTokenProvider)

        let chat = try SecureChat(context: context)

        // TODO: Setup timer with key rotation. Post error or delegate
        // TODO: Print rotation logs
        // TODO: Handle case when user is not registered yet
        _ = try chat.rotateKeys().startSync().get()

        self.secureChat = chat
    }

    internal func getSecureChat() throws -> SecureChat {
        guard let secureChat = self.secureChat else {
            throw NSError()
        }

        return secureChat
    }
}

extension REThree {
    internal override func privateKeyChanged(newCard: Card? = nil) throws {
        try super.privateKeyChanged()

        try self.setupSecureChat()
    }

    internal override func privateKeyDeleted() throws {
        try super.privateKeyDeleted()

        self.secureChat = nil
    }
}
