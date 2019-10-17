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

extension EThree {
    open func createRatchetChat(with card: Card, name: String? = nil) -> GenericOperation<RatchetChat> {
        return CallbackOperation { _, completion in
            do {
                let secureChat = try self.getSecureChat()

                guard secureChat.existingSession(withParticipantIdentity: card.identity, name: name) == nil else {
                    throw EThreeRatchetError.chatAlreadyExists
                }

                guard card.identity != self.identity else {
                    throw EThreeRatchetError.selfChatIsForbidden
                }

                let session = try secureChat.startNewSessionAsSender(receiverCard: card, name: name)
                    .startSync()
                    .get()

                let ticket = try session.encrypt(string: UUID().uuidString)

                try self.cloudRatchetStorage.store(ticket, sharedWith: card, name: name)

                try secureChat.storeSession(session)

                let ratchetChat = RatchetChat(session: session,
                                              sessionStorage: secureChat.sessionStorage)

                completion(ratchetChat, nil)
            }
            catch let error as ServiceError where error.errorCode == RatchetServiceError.noKeyDataForUser.rawValue {
                completion(nil, EThreeRatchetError.userIsNotUsingRatchet)
            }
            catch KeyknoxClientError.invalidPreviousHashHeader {
                completion(nil, EThreeRatchetError.chatAlreadyExists)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    open func joinRatchetChat(with card: Card, name: String? = nil) -> GenericOperation<RatchetChat> {
        return CallbackOperation { _, completion in
            do {
                let secureChat = try self.getSecureChat()

                guard secureChat.existingSession(withParticipantIdentity: card.identity, name: name) == nil else {
                    throw EThreeRatchetError.chatAlreadyExists
                }

                guard card.identity != self.identity else {
                    throw EThreeRatchetError.selfChatIsForbidden
                }

                let ticket = try self.cloudRatchetStorage.retrieve(from: card, name: name)

                let session = try secureChat.startNewSessionAsReceiver(senderCard: card, ratchetMessage: ticket)
                _ = try session.decryptData(from: ticket)
                try secureChat.storeSession(session)

                let ratchetChat = RatchetChat(session: session, sessionStorage: secureChat.sessionStorage)

                completion(ratchetChat, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    open func getRatchetChat(with card: Card, name: String? = nil) throws -> RatchetChat? {
        let secureChat = try self.getSecureChat()

        guard let session = secureChat.existingSession(withParticipantIdentity: card.identity, name: name) else {
            return nil
        }

        return RatchetChat(session: session, sessionStorage: secureChat.sessionStorage)
    }

    open func deleteRatchetChat(with card: Card, name: String? = nil) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let secureChat = try self.getSecureChat()

                try self.cloudRatchetStorage.delete(card: card, name: name)

                do {
                    try secureChat.deleteSession(withParticipantIdentity: card.identity, name: name)
                } catch CocoaError.fileNoSuchFile {
                    throw EThreeRatchetError.missingLocalChat
                }

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
