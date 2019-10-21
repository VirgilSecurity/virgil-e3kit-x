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

// MARK: - Extension with key back-up operations
extension EThree {
    /// Derives different passwords for login and for backup from one
    /// - Parameter password: password to derive from
    @objc open func derivePasswords(from password: String) -> DerivedPasswords {
        let passwordData = password.data(using: .utf8)!

        let hash1 = self.crypto.computeHash(for: passwordData, using: .sha256)
        let hash2 = self.crypto.computeHash(for: hash1, using: .sha512)

        let loginPassword = hash2.subdata(in: 0..<32).base64EncodedString()
        let backupPassword = hash2.subdata(in: 32..<64).base64EncodedString()

        return DerivedPasswords(loginPassword: loginPassword, backupPassword: backupPassword)
    }

    /// Encrypts user's private key using password and backs up the encrypted
    /// private key to Virgil's cloud. This enables users to log in from other devices
    /// and have access to their private key to decrypt data.
    ///
    /// - Parameter password: String with password
    /// - Returns: CallbackOperation<Void>
    /// - Important: Requires private key in local storage
    open func backupPrivateKey(password: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let identityKeyPair = try self.localKeyStorage.retrieveKeyPair()

                try self.cloudKeyManager.store(key: identityKeyPair.privateKey, usingPassword: password)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Restores encrypted private key from Virgil's cloud, decrypts it using
    /// user's password and saves it in local storage
    ///
    /// - Parameter password: String with password
    /// - Returns: CallbackOperation<Void>
    open func restorePrivateKey(password: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let entry = try self.cloudKeyManager.retrieve(usingPassword: password)

                let card = try self.lookupManager.lookupCard(of: self.identity)

                try self.localKeyStorage.store(data: entry.data)

                let params = PrivateKeyChangedParams(card: card, isNew: false)
                try self.privateKeyChanged(params: params)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Changes the password on a backed-up private key.
    ///
    /// - Parameters:
    ///   - oldOne: old password
    ///   - newOne: new password
    /// - Returns: CallbackOperation<Void>
    open func changePassword(from oldOne: String, to newOne: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.cloudKeyManager.changePassword(from: oldOne, to: newOne)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Deletes Private Key stored on Virgil's cloud. This will disable user to log in from other devices.
    ///
    /// - Parameter password: String with password
    /// - Returns: CallbackOperation<Void>
    open func resetPrivateKeyBackup(password: String? = nil) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                if let password = password {
                    try self.cloudKeyManager.delete(password: password)
                } else {
                    try self.cloudKeyManager.deleteAll()
                }

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
