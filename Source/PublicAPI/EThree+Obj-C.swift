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

// MARK: - Extension with Objective-C compatible operations
extension EThree {
    /// Initializes E3Kit with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify changing of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    ///   - completion: completion handler
    ///   - ethree: initialized EThree instance
    ///   - error: corresponding error
    @objc public static func initialize(tokenCallback: @escaping RenewJwtCallback,
                                        storageParams: KeychainStorageParams? = nil,
                                        completion: @escaping (_ ethree: EThree?, _ error: Error?) -> Void) {
        EThree.initialize(tokenCallback: tokenCallback, storageParams: storageParams).start(completion: completion)
    }

    /// Generates new Private Key, publishes Card on Virgil Cards Service and saves Private Key in local storage
    ///
    /// - Parameters:
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc public func register(completion: @escaping (_ error: Error?) -> Void) {
        self.register().start { _, error in
            completion(error)
        }
    }

    /// Generates new Private Key, publishes new Card to replace the current one on Virgil Cards Service
    /// and saves new Private Key in local storage
    ///
    /// - Parameter completion: completion handler
    ///   - error: corresponding error
    @objc public func rotatePrivateKey(completion: @escaping (_ error: Error?) -> Void) {
        self.rotatePrivateKey().start { _, error in
            completion(error)
        }
    }

    /// Revokes Card from Virgil Cards Service, deletes Private Key from local storage
    ///
    /// - Parameter completion: completion handler
    ///   - error: corresponding error
    @objc public func unregister(completion: @escaping (_ error: Error?) -> Void) {
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
    @objc public func backupPrivateKey(password: String, completion: @escaping (_ error: Error?) -> Void) {
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
    @objc public func restorePrivateKey(password: String, completion: @escaping (_ error: Error?) -> Void) {
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
    @objc public func changePassword(from oldOne: String, to newOne: String,
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
    @objc public func resetPrivateKeyBackup(password: String? = nil, completion: @escaping (_ error: Error?) -> Void) {
        self.resetPrivateKeyBackup(password: password).start { _, error in
            completion(error)
        }
    }

    /// Retrieves users Cards from the Virgil Cloud or local storage if exists
    ///
    /// - Parameters:
    ///   - identities: array of identities to search for
    ///   - forceReload: will not use local cached cards if true
    ///   - completion: completion handler
    ///   - lookupResult: dictionary with idenities as keys and found Cards as values
    ///   - error: corresponding error
    @objc public func lookupCards(of identities: [String],
                                  forceReload: Bool = false,
                                  completion: @escaping (_ lookupResult: LookupResult?,
                                                         _ error: Error?) -> Void) {
        self.lookupCards(of: identities, forceReload: forceReload).start(completion: completion)
    }

    /// Retrieves user Card from the Virgil Cloud or local storage if exists
    ///
    /// - Parameters:
    ///   - identity: identity to search from
    ///   - forceReload: will not use local cached card if true
    ///   - completion: completion handler
    ///   - card: found Card
    ///   - error: corresponding error
    @objc public func lookupCard(of identity: String,
                                 forceReload: Bool = false,
                                 completion: @escaping (_ card: Card?,
                                                        _ error: Error?) -> Void) {
        self.lookupCard(of: identity, forceReload: forceReload).start(completion: completion)
    }

    /// Creates group, saves in cloud and locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - lookup: Cards of participants. Result of lookupCards call
    ///   - completion: completion handler
    ///   - group: created `Group`
    ///   - error: corresponding error
    @objc public func createGroup(id identifier: Data,
                                  with lookup: LookupResult,
                                  completion: @escaping (_ group: Group?,
                                                         _ error: Error?) -> Void) {
        self.createGroup(id: identifier, with: lookup).start(completion: completion)
    }

    /// Loads group from cloud, saves locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - card: Card of group initiator
    ///   - completion: completion handler
    ///   - group: loaded `Group`
    ///   - error: corresponding error
    @objc public func loadGroup(id identifier: Data,
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
    @objc public func deleteGroup(id identifier: Data, completion: @escaping (_ error: Error?) -> Void) {
        self.deleteGroup(id: identifier).start { _, error in
            completion(error)
        }
    }

    /// Retrieves users Cards from the Virgil Cloud or local storage if exists
    ///
    /// - Parameters:
    ///   - identities: array of identities to search for
    ///   - forceReload: will not use local cached cards if true
    ///   - lookupResult: dictionary with idenities as keys and found cards as values
    ///   - error: corresponding error
    /// - Returns: CallbackOperation<LookupResult>
    @available(*, deprecated, renamed: "lookupCards")
    @objc public func lookupPublicKeys(of identities: [String],
                                       forceReload: Bool = false,
                                       completion: @escaping (_ lookupResult: LookupResult?,
                                                              _ error: Error?) -> Void) {
        self.lookupPublicKeys(of: identities, forceReload: forceReload).start(completion: completion)
    }
}
