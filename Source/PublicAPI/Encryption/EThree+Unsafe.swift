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

extension EThree {
    /// Creates chat with unregistered user
    ///
    /// - Important: Temporary key for unregistered user is stored unencrypted.
    ///
    /// - Parameter identity: identity of unregistered user
    open func createUnsafeChat(with identity: String) -> GenericOperation<UnsafeChat> {
        return CallbackOperation { _, completion in
            do {
                guard identity != self.identity else {
                    throw UnsafeChatError.selfChatIsForbidden
                }

                let result = try self.findUsers(with: [identity], checkResult: false).startSync().get()

                guard result.isEmpty else {
                    throw UnsafeChatError.userIsRegistered
                }

                let unsafeChat = try self.getUnsafeManager().create(with: identity)

                completion(unsafeChat, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Loads unsafe chat by fetching temporary key form Cloud
    /// - Parameters:
    ///   - asCreator: Bool to specify wether caller is creator of chat or not
    ///   - identity: identity of participant
    open func loadUnsafeChat(asCreator: Bool, with identity: String) -> GenericOperation<UnsafeChat> {
        return CallbackOperation { _, completion in
            do {
                guard identity != self.identity else {
                    throw UnsafeChatError.selfChatIsForbidden
                }

                let unsafeChat = try self.getUnsafeManager().load(asCreator: asCreator,
                                                                  with: identity)

                completion(unsafeChat, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Returns cached unsafe chat
    /// - Parameter identity: identity of participant
    open func getUnsafeChat(with identity: String) throws -> UnsafeChat? {
        let unsafeManager = try self.getUnsafeManager()

        return try unsafeManager.get(with: identity)
    }

    /// Deletes unsafe chat from cloud (if user is owner) and local storage
    /// - Parameter identity: identity of participant
    open func deleteUnsafeChat(with identity: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.getUnsafeManager().delete(with: identity)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
