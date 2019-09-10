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
import VirgilCryptoRatchet

extension REThree {
    private func getSessionAsReceiver(message: RatchetMessage, receiverCard card: Card) throws -> SecureSession {
        let secureChat = try self.getSecureChat()

        return try secureChat.existingSession(withParticipantIdentity: card.identity) ??
            secureChat.startNewSessionAsReceiver(senderCard: card, ratchetMessage: message)
    }

    public func isChatStarted(with identity: String) throws -> Bool {
        return try self.getSecureChat().existingSession(withParticipantIdentity: identity) != nil
    }

    public func startChat(with card: Card) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let secureChat = try self.getSecureChat()

                let session = try secureChat.startNewSessionAsSender(receiverCard: card).startSync().get()

                try secureChat.storeSession(session)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    @objc public func encrypt(text: String, for card: Card) throws -> String {
        let secureChat = try self.getSecureChat()

        guard let session = secureChat.existingSession(withParticipantIdentity: card.identity) else {
            throw NSError()
        }

        let ratchetMessage = try session.encrypt(string: text)

        try secureChat.storeSession(session)

        return ratchetMessage.serialize().base64EncodedString()
    }

    @objc public func decrypt(text: String, from card: Card) throws -> String {
        let secureChat = try self.getSecureChat()

        guard let data = Data(base64Encoded: text) else {
            throw NSError()
        }

        let message = try RatchetMessage.deserialize(input: data)

        let session = try self.getSessionAsReceiver(message: message, receiverCard: card)

        let decrypted = try session.decryptString(from: message)

        try secureChat.storeSession(session)

        return decrypted
    }

    @objc public func encrypt(data: Data, for card: Card) throws -> Data {
        let secureChat = try self.getSecureChat()

        guard let session = secureChat.existingSession(withParticipantIdentity: card.identity) else {
            throw NSError()
        }

        let ratchetMessage = try session.encrypt(data: data)

        try secureChat.storeSession(session)

        return ratchetMessage.serialize()
    }

    @objc public func decrypt(data: Data, from card: Card) throws -> Data {
        let secureChat = try self.getSecureChat()

        let message = try RatchetMessage.deserialize(input: data)

        let session = try self.getSessionAsReceiver(message: message, receiverCard: card)

        let decrypted = try session.decryptData(from: message)

        try secureChat.storeSession(session)

        return decrypted
    }

    @objc public func decryptMultiple(data: NSOrderedSet, from card: Card) throws -> Data {
        // TODO: Implement
        throw NSError()
    }
}

