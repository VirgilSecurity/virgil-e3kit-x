//
// Copyright (C) 2015-2018 Virgil Security Inc.
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

import VirgilCryptoApiImpl
import VirgilSDK
import VirgilSDKKeyknox
import VirgilSDKPythia

internal class CloudKeyManager {
    internal let identity: String
    internal let accessTokenProvider: AccessTokenProvider
    internal let keychainStorage: KeychainStorage
    internal let crypto: VirgilCrypto
    internal let brainKey: BrainKey

    internal init(identity: String, accessTokenProvider: AccessTokenProvider,
                  crypto: VirgilCrypto, keychainStorage: KeychainStorage) {
        self.identity = identity
        self.accessTokenProvider = accessTokenProvider
        self.keychainStorage = keychainStorage
        let brainKeyContext = BrainKeyContext.makeContext(accessTokenProvider: accessTokenProvider)
        self.crypto = crypto
        self.brainKey = BrainKey(context: brainKeyContext)
    }

    internal func setUpCloudKeyStorage(password: String, completion: @escaping (CloudKeyStorage?, Error?) -> ()) {
        self.brainKey.generateKeyPair(password: password).start { brainKeyPair, error in
            guard let brainKeyPair = brainKeyPair, error == nil else {
                completion(nil, error)
                return
            }

            do {
                let cloudKeyStorage = try CloudKeyStorage(accessTokenProvider: self.accessTokenProvider,
                                                          publicKeys: [brainKeyPair.publicKey],
                                                          privateKey: brainKeyPair.privateKey)

                cloudKeyStorage.retrieveCloudEntries { completion(cloudKeyStorage, $0) }
            } catch {
                completion(nil, error)
            }
        }
    }
}

extension CloudKeyManager {
    internal func store(key: VirgilPrivateKey, usingPassword password: String,
                        completion: @escaping (Error?) -> ()) {
        self.setUpCloudKeyStorage(password: password) { cloudKeyStorage, error in
            guard let cloudKeyStorage = cloudKeyStorage, error == nil else {
                completion(error)
                return
            }

            let exportedIdentityKey = self.crypto.exportPrivateKey(key)

            cloudKeyStorage.storeEntry(withName: self.identity, data: exportedIdentityKey) { error in
                completion(error)
            }
        }
    }

    internal func retrieve(usingPassword password: String,
                           completion: @escaping (CloudEntry?, Error?) -> ()) {
        self.setUpCloudKeyStorage(password: password) { cloudKeyStorage, error in
            guard let cloudKeyStorage = cloudKeyStorage, error == nil else {
                completion(nil, error)
                return
            }

            do {
                let entry = try cloudKeyStorage.retrieveEntry(withName: self.identity)

                completion(entry, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    internal func delete(password: String, completion: @escaping (Error?) -> ()) {
        self.setUpCloudKeyStorage(password: password) { cloudKeyStorage, error in
            guard let cloudKeyStorage = cloudKeyStorage, error == nil else {
                completion(error)
                return
            }

            cloudKeyStorage.deleteEntry(withName: self.identity) { error in
                guard error == nil else {
                    completion(error)
                    return
                }

                completion(nil)
            }
        }
    }

    internal func changePassword(from oldPassword: String, to newPassword: String,
                                 completion: @escaping (Error?) -> ()) {
        self.setUpCloudKeyStorage(password: oldPassword) { cloudKeyStorage, error in
            guard let cloudKeyStorage = cloudKeyStorage, error == nil else {
                completion(error)
                return
            }

            sleep(2)

            self.brainKey.generateKeyPair(password: newPassword).start { brainKeyPair, error in
                guard let brainKeyPair = brainKeyPair, error == nil else {
                    completion(error)
                    return
                }

                cloudKeyStorage.updateRecipients(newPublicKeys: [brainKeyPair.publicKey],
                                                 newPrivateKey: brainKeyPair.privateKey) { error in
                    completion(error)
                }
            }
        }
    }
}
