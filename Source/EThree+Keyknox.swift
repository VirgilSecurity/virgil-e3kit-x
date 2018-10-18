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

extension EThree {
    internal func publishToKeyknox(key: VirgilPrivateKey, usingPassword password: String,
                                   completion: @escaping (KeychainEntry?, Error?) -> ()) {
        self.setUpSyncKeyStorage(password: password) { syncKeyStorage, error in
            guard let syncKeyStorage = syncKeyStorage, error == nil else {
                completion(nil, error)
                return
            }

            do {
                let exportedIdentityKey = try self.privateKeyExporter.exportPrivateKey(privateKey: key)

                syncKeyStorage.storeEntry(withName: self.identity, data: exportedIdentityKey) { entry, error in
                    completion(entry, error)
                }
            } catch {
                completion(nil, error)
            }
        }
    }

    internal func fetchFromKeyknox(usingPassword password: String,
                                   completion: @escaping (KeychainEntry?, Error?) -> ()) {
        self.setUpSyncKeyStorage(password: password) { syncKeyStorage, error in
            guard let syncKeyStorage = syncKeyStorage, error == nil else {
                completion(nil, error)
                return
            }

            do {
                let entry = try syncKeyStorage.retrieveEntry(withName: self.identity)

                completion(entry, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    internal func deleteKeyknoxEntry(password: String, completion: @escaping (Error?) -> ()) {
        self.setUpSyncKeyStorage(password: password) { syncKeyStorage, error in
            guard let syncKeyStorage = syncKeyStorage, error == nil else {
                completion(error)
                return
            }

            syncKeyStorage.deleteEntry(withName: self.identity) { error in
                guard error == nil else {
                    completion(error)
                    return
                }
            }
        }
    }

    internal func changeKeyknoxPassword(from oldPassword: String, to newPassword: String,
                                        completion: @escaping (Error?) -> ()) {
        self.setUpSyncKeyStorage(password: oldPassword) { syncKeyStorage, error in
            guard let syncKeyStorage = syncKeyStorage, error == nil else {
                completion(error)
                return
            }

            self.generateBrainKey(password: newPassword) { brainKeyPair, error in
                guard let brainKeyPair = brainKeyPair, error == nil else {
                    completion(error)
                    return
                }
                syncKeyStorage.updateRecipients(newPublicKeys: [brainKeyPair.publicKey],
                                                newPrivateKey: brainKeyPair.privateKey) { error in
                    completion(error)
                }
            }
        }
    }

    internal func setUpSyncKeyStorage(password: String, completion: @escaping (SyncKeyStorage?, Error?) -> ()) {
        self.generateBrainKey(password: password) { brainKeyPair, error in
            guard let brainKeyPair = brainKeyPair, error == nil else {
                completion(nil, error)
                return
            }

            do {
                let syncKeyStorage = try self.generateSyncKeyStorage(keyPair: brainKeyPair)

                syncKeyStorage.sync { error in
                    completion(syncKeyStorage, error)
                }
            } catch {
                completion(nil, error)
            }
        }
    }

    internal func generateSyncKeyStorage(keyPair: VirgilKeyPair) throws -> SyncKeyStorage {
        let cloudKeyStorage = try CloudKeyStorage(accessTokenProvider: self.cardManager.accessTokenProvider,
                                                  publicKeys: [keyPair.publicKey], privateKey: keyPair.privateKey)
        let syncKeyStorage = SyncKeyStorage(identity: self.identity, keychainStorage: self.keychainStorage,
                                            cloudKeyStorage: cloudKeyStorage)

        return syncKeyStorage
    }

    internal func generateBrainKey(password: String, brainKeyId: String? = nil,
                                   completion: @escaping (VirgilKeyPair?, Error?) -> ()) {
        let brainKeyContext = BrainKeyContext.makeContext(accessTokenProvider: cardManager.accessTokenProvider)
        let brainKey = BrainKey(context: brainKeyContext)

        brainKey.generateKeyPair(password: password, brainKeyId: brainKeyId) { brainKeyPair, error in
            completion(brainKeyPair, error)
        }
    }
}
