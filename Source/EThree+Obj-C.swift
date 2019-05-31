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

extension EThree {
    /// Initializes E3Kit with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
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

    /// Encrypts the user's private key using the user's password and backs up the encrypted
    /// private key to Virgil's cloud. This enables users to log in from other devices and have
    /// access to their private key to decrypt data.
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

    /// Restores the encrypted private key from Virgil's cloud, decrypts it using
    /// the user's password and saves it in local storage
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

    /// Retrieves user public keys from the cloud for encryption/verification.
    ///
    /// Important: Avoid identities duplication
    /// - Parameters:
    ///   - identities: array of identities to search for
    ///   - completion: completion handler
    ///   - lookupResult: dictionary with idenities as keys and found public keys as values
    ///   - error: corresponding error
    @objc public func lookupPublicKeys(of identities: [String],
                                       completion: @escaping (_ lookupResult: LookupResult?,
                                                              _ error: Error?) -> Void) {
        self.lookupPublicKeys(of: identities).start(completion: completion)
    }
}