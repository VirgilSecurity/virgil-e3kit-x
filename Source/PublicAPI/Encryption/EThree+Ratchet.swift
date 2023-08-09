//
// Copyright (C) 2015-2021 Virgil Security Inc.
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

import Foundation
import VirgilCryptoRatchet
import VirgilSDK
import VirgilSDKRatchet

// MARK: - Extension with Double Ratchet operations
extension EThree {
    /// Creates double ratchet channel with user, saves it locally
    /// - Parameters:
    ///   - card: Card of participant
    ///   - name: name of channel
    public func createRatchetChannel(with card: Card, name: String? = nil) -> GenericOperation<RatchetChannel> {
        return CallbackOperation { _, completion in
            do {
                let secureChat = try self.getSecureChat()

                guard secureChat.existingSession(withParticipantIdentity: card.identity, name: name) == nil else {
                    throw EThreeRatchetError.channelAlreadyExists
                }

                guard card.identity != self.identity else {
                    throw EThreeRatchetError.selfChannelIsForbidden
                }

                let session = try self.startRatchetSessionAsSender(
                    secureChat: secureChat,
                    receiverCard: card,
                    name: name
                )

                let ticket = try session.encrypt(string: UUID().uuidString)

                try self.cloudRatchetStorage.store(ticket, sharedWith: card, name: name)

                try secureChat.storeSession(session)

                let ratchetChannel = RatchetChannel(
                    session: session,
                    sessionStorage: secureChat.sessionStorage
                )

                completion(ratchetChannel, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Joins double ratchet channel with user, saves it locally
    /// - Parameters:
    ///   - card: Card of initiator
    ///   - name: name of channel
    public func joinRatchetChannel(with card: Card, name: String? = nil) -> GenericOperation<RatchetChannel> {
        return CallbackOperation { _, completion in
            do {
                let secureChat = try self.getSecureChat()

                guard secureChat.existingSession(withParticipantIdentity: card.identity, name: name) == nil else {
                    throw EThreeRatchetError.channelAlreadyExists
                }

                guard card.identity != self.identity else {
                    throw EThreeRatchetError.selfChannelIsForbidden
                }

                let ticket = try self.cloudRatchetStorage.retrieve(from: card, name: name)

                let session = try secureChat.startNewSessionAsReceiver(
                    senderCard: card,
                    ratchetMessage: ticket,
                    enablePostQuantum: Defaults.enableRatchetPqc
                )
                _ = try session.decryptData(from: ticket)
                try secureChat.storeSession(session)

                let ratchetChannel = RatchetChannel(session: session, sessionStorage: secureChat.sessionStorage)

                completion(ratchetChannel, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Retrieves double ratchet channel from local storage
    /// - Parameters:
    ///   - card: Card of participant
    ///   - name: name of channel
    public func getRatchetChannel(with card: Card, name: String? = nil) throws -> RatchetChannel? {
        return try self.getRatchetChannel(with: card.identity, name: name)
    }

    /// Deletes double ratchet channel from cloud (if user is creator) and local storage
    /// - Parameters:
    ///   - card: Card of participant
    ///   - name: name of channel
    public func deleteRatchetChannel(with card: Card, name: String? = nil) -> GenericOperation<Void> {
        return self.deleteRatchetChannel(with: card.identity, name: name)
    }
}

extension EThree {
    /// Creates double ratchet channel with user, saves it locally
    /// - Parameters:
    ///   - identity: participant identity
    ///   - name: name of channel
    public func createRatchetChannel(with identity: String, name: String? = nil) -> GenericOperation<RatchetChannel> {
        return CallbackOperation { _, completion in
            do {
                let card = try self.findUser(with: identity).startSync().get()

                self.createRatchetChannel(with: card, name: name).start(completion: completion)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Joins double ratchet channel with user, saves it locally
    /// - Parameters:
    ///   - initiator: initiator identity
    ///   - name: name of channel
    public func joinRatchetChannel(with initiator: String, name: String? = nil) -> GenericOperation<RatchetChannel> {
        return CallbackOperation { _, completion in
            do {
                let card = try self.findUser(with: initiator).startSync().get()

                self.joinRatchetChannel(with: card, name: name).start(completion: completion)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Retrieves double ratchet channel from local storage
    /// - Parameters:
    ///   - participant: participant identity
    ///   - name: name of channel
    public func getRatchetChannel(with participant: String, name: String? = nil) throws -> RatchetChannel? {
        let secureChat = try self.getSecureChat()

        guard let session = secureChat.existingSession(withParticipantIdentity: participant, name: name) else {
            return nil
        }

        return RatchetChannel(session: session, sessionStorage: secureChat.sessionStorage)
    }

    /// Deletes double ratchet channel from cloud (if user is creator) and local storage
    /// - Parameters:
    ///   - participant: participant identity
    ///   - name: name of channel
    public func deleteRatchetChannel(with participant: String, name: String? = nil) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let secureChat = try self.getSecureChat()

                try self.cloudRatchetStorage.delete(identity: participant, name: name)

                do {
                    try secureChat.deleteSession(withParticipantIdentity: participant, name: name)
                } catch CocoaError.fileNoSuchFile {}

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
