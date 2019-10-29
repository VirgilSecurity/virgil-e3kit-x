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

// MARK: - Extension with Objective-C compatible operations
extension EThree {
    /// Generates new Private Key, publishes Card on Virgil Cards Service and saves Private Key in local storage
    ///
    /// - Parameters:
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func register(completion: @escaping (_ error: Error?) -> Void) {
        self.register().start { _, error in
            completion(error)
        }
    }

    /// Uses provided Private Key to publish Card to Virgil Cards Service. Saves Private Key in local storage
    ///
    /// - Parameter keyPair: Key Pair to publish Card with
    @objc open func register(with keyPair: VirgilKeyPair, completion: @escaping (_ error: Error?) -> Void) {
        self.register(with: keyPair).start { _, error in
            completion(error)
        }
    }

    /// Generates new Private Key, publishes new Card to replace the current one on Virgil Cards Service
    /// and saves new Private Key in local storage
    ///
    /// - Parameter completion: completion handler
    ///   - error: corresponding error
    @objc open func rotatePrivateKey(completion: @escaping (_ error: Error?) -> Void) {
        self.rotatePrivateKey().start { _, error in
            completion(error)
        }
    }

    /// Revokes Card from Virgil Cards Service, deletes Private Key from local storage
    ///
    /// - Parameter completion: completion handler
    ///   - error: corresponding error
    @objc open func unregister(completion: @escaping (_ error: Error?) -> Void) {
        self.unregister().start { _, error in
            completion(error)
        }
    }

    /// Encrypts user's private key using password and backs up the encrypted
    /// private key to Virgil's cloud. This enables users to log in from other devices
    /// and have access to their private key to decrypt data.
    ///
    /// - Parameters:
    ///   - password: String with password
    ///   - completion: completion handler
    ///   - error: corresponding error
    /// - Important: Requires private key in local storage
    @objc open func backupPrivateKey(password: String, completion: @escaping (_ error: Error?) -> Void) {
        self.backupPrivateKey(password: password).start { _, error in
            completion(error)
        }
    }

    /// Restores encrypted private key from Virgil's cloud, decrypts it using
    /// user's password and saves it in local storage
    ///
    /// - Parameters:
    ///   - password: String with password
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func restorePrivateKey(password: String, completion: @escaping (_ error: Error?) -> Void) {
        self.restorePrivateKey(password: password).start { _, error in
            completion(error)
        }
    }

    /// Changes the password on a backed-up private key.
    ///
    /// - Parameters:
    ///   - oldOne: old password
    ///   - newOne: new password
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func changePassword(from oldOne: String, to newOne: String,
                                   completion: @escaping (_ error: Error?) -> Void) {
        self.changePassword(from: oldOne, to: newOne).start { _, error in
            completion(error)
        }
    }

    /// Deletes Private Key stored on Virgil's cloud. This will disable user to log in from other devices.
    ///
    /// - Parameters:
    ///   - password: String with password
    ///   - completion: completion handler
    ///   - error: corresponding error
    /// - Important: If password specified it will reset entry with current identity.
    ///              Otherwise it will reset ALL entries.
    @objc open func resetPrivateKeyBackup(password: String? = nil, completion: @escaping (_ error: Error?) -> Void) {
        self.resetPrivateKeyBackup(password: password).start { _, error in
            completion(error)
        }
    }

    /// Retrieves users Cards from the Virgil Cloud or local storage if exists
    ///
    /// - Parameters:
    ///   - identities: array of identities to find
    ///   - forceReload: will not use local cached cards if true
    ///   - checkResult: checks that cards for all identities were found if true
    ///   - completion: completion handler
    ///   - find: dictionary with idenities as keys and found Cards as values
    ///   - error: corresponding error
    @objc open func findUsers(with identities: [String],
                              forceReload: Bool = false,
                              checkResult: Bool = true,
                              completion: @escaping (_ findResult: FindUsersResult?,
                                                     _ error: Error?) -> Void) {
        self.findUsers(with: identities,
                       forceReload: forceReload,
                       checkResult: checkResult)
            .start(completion: completion)
    }

    /// Retrieves user Card from the Virgil Cloud or local storage if exists
    ///
    /// - Parameters:
    ///   - identity: identity to find
    ///   - forceReload: will not use local cached card if true
    ///   - completion: completion handler
    ///   - card: found Card
    ///   - error: corresponding error
    @objc open func findUser(with identity: String,
                             forceReload: Bool = false,
                             completion: @escaping (_ card: Card?,
                                                    _ error: Error?) -> Void) {
        self.findUser(with: identity, forceReload: forceReload).start(completion: completion)
    }

    /// Updates local cached cards
    /// - Parameters:
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func updateCachedUsers(completion: @escaping (_ error: Error?) -> Void) {
        self.updateCachedUsers().start { _, error in
            completion(error)
        }
    }

    /// Creates group, saves in cloud and locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - findResult: Cards of participants. Result of findUsers call
    ///   - completion: completion handler
    ///   - group: created `Group`
    ///   - error: corresponding error
    @objc(createGroupWithDataId:findResult:completion:)
    open func createGroup(id identifier: Data,
                          with findResult: FindUsersResult,
                          completion: @escaping (_ group: Group?,
                                                 _ error: Error?) -> Void) {
        self.createGroup(id: identifier, with: findResult).start(completion: completion)
    }

    /// Loads group from cloud, saves locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - card: Card of group initiator
    ///   - completion: completion handler
    ///   - group: loaded `Group`
    ///   - error: corresponding error
    @objc(loadGroupWithDataId:initiator:completion:)
    open func loadGroup(id identifier: Data,
                        initiator card: Card,
                        completion: @escaping (_ group: Group?,
                                               _ error: Error?) -> Void) {
        self.loadGroup(id: identifier, initiator: card).start(completion: completion)
    }

    /// Deletes group from cloud and local storage
    ///
    /// - Parameters
    ///   - identifier: identifier of group
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc(deleteGroupWithDataId:completion:)
    open func deleteGroup(id identifier: Data, completion: @escaping (_ error: Error?) -> Void) {
        self.deleteGroup(id: identifier).start { _, error in
            completion(error)
        }
    }

    /// Creates group, saves in cloud and locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - findResult: Cards of participants. Result of findUsers call
    ///   - completion: completion handler
    ///   - group: created `Group`
    ///   - error: corresponding error
    @objc(createGroupWithStringId:findResult:completion:)
    open func createGroup(id identifier: String,
                          with findResult: FindUsersResult,
                          completion: @escaping (_ group: Group?,
                                                 _ error: Error?) -> Void) {
        self.createGroup(id: identifier, with: findResult).start(completion: completion)
    }

    /// Loads group from cloud, saves locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - card: Card of group initiator
    ///   - completion: completion handler
    ///   - group: loaded `Group`
    ///   - error: corresponding error
    @objc(loadGroupWithStringId:initiator:completion:)
    open func loadGroup(id identifier: String,
                        initiator card: Card,
                        completion: @escaping (_ group: Group?,
                                               _ error: Error?) -> Void) {
        self.loadGroup(id: identifier, initiator: card).start(completion: completion)
    }

    /// Deletes group from cloud and local storage
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc(deleteGroupWithStringId:completion:)
    open func deleteGroup(id identifier: String, completion: @escaping (_ error: Error?) -> Void) {
        self.deleteGroup(id: identifier).start { _, error in
            completion(error)
        }
    }

    /// Creates double ratchet chat with user, saves it locally
    /// - Parameters:
    ///   - card: Card of participant
    ///   - name: name of chat
    ///   - completion: completion handler
    ///   - chat: created `RatchetChat` intance
    ///   - error: corresponding error
    @objc open func createRatchetChat(with card: Card,
                                      name: String? = nil,
                                      completion: @escaping (_ chat: RatchetChat?,
                                                             _ error: Error?) -> Void) {
        self.createRatchetChat(with: card, name: name).start(completion: completion)
    }

    /// Joins double ratchet chat with user, saves it locally
    /// - Parameters:
    ///   - card: Card of initiator
    ///   - name: name of chat
    ///   - completion: completion handler
    ///   - chat: `RatchetChat` intance
    ///   - error: corresponding error
    @objc open func joinRatchetChat(with card: Card,
                                    name: String? = nil,
                                    completion: @escaping (_ chat: RatchetChat?,
                                                           _ error: Error?) -> Void) {
        self.joinRatchetChat(with: card, name: name).start(completion: completion)
    }

    /// Deletes double ratchet chat
    /// - Parameters:
    ///   - card: Card of participant
    ///   - name: name of chat
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func deleteRatchetChat(with card: Card,
                                      name: String? = nil,
                                      completion: @escaping (_ error: Error?) -> Void) {
        self.deleteRatchetChat(with: card, name: name).start { _, error in
            completion(error)
        }
    }
}
