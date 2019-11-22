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
    open func bootstrap(password: String? = nil) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.boostrapInternal(password: password)

                completion((), nil)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    open func rotateBootstrap(password: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.cloudKeyManager.resetBrainKeyCache()

                try self.resetPrivateKeyBackup().startSync().get()

                if try self.hasLocalPrivateKey() {
                    try self.cleanUp()
                }

                try self.rotatePrivateKey().startSync().get()

                try self.backupPrivateKey(password: password).startSync().get()

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}

extension EThree {
    internal func boostrapInternal(password: String?) throws {
        do {
            let selfCard = try self.findUser(with: self.identity, forceReload: true)
                .startSync()
                .get()

            if try self.hasLocalPrivateKey() {
                let key = try self.localKeyStorage.retrieveKeyPair()

                if key.identifier != selfCard.publicKey.identifier {
                    try self.cleanUp()

                    try self.restoreUser(password: password, selfCard: selfCard)
                }

                try self.checkBackup(password: password, selfCard: selfCard)
            }
            else {
                try self.restoreUser(password: password, selfCard: selfCard)
            }
        }
        catch FindUsersError.cardWasNotFound {
            try self.createUser(password: password)
        }
    }

    /// Registeres user on Virgil Cloud and backs up Private Key
    /// - Parameter password: backup password
    internal func createUser(password: String?) throws {
        try self.register().startSync().get()

        let keyPair = try self.localKeyStorage.retrieveKeyPair()

        do {
            try self.cloudKeyManager.store(key: keyPair.privateKey, password: password)
        }
        catch CloudKeyStorageError.entryAlreadyExists {
            try self.resetPrivateKeyBackup().startSync().get()

            try self.cloudKeyManager.store(key: keyPair.privateKey, password: password)
        }
    }

    /// Restores user Private Key
    /// - Parameters:
    ///   - password: backup password
    ///   - selfCard: Self Card
    internal func restoreUser(password: String?, selfCard: Card) throws {
        do {
            let entry = try self.cloudKeyManager.retrieve(usingPassword: password)

            let keyPair = try self.crypto.importPrivateKey(from: entry.data)

            guard keyPair.identifier == selfCard.publicKey.identifier else {
                try self.resetPrivateKeyBackup().startSync().get()

                throw EThreeError.unfinishedBootstrapOnOriginDevice
            }

            try self.localKeyStorage.store(data: entry.data)

            let params = PrivateKeyChangedParams(card: selfCard, isNew: false)
            try self.privateKeyChanged(params: params)

        }
        catch CloudKeyStorageError.entryNotFound {
            throw EThreeError.unfinishedBootstrapOnOriginDevice
        }
    }

    internal func checkBackup(password: String?, selfCard: Card) throws {
        do {
            let entry = try self.cloudKeyManager.retrieve(usingPassword: password)

            let keyPair = try self.crypto.importPrivateKey(from: entry.data)

            if keyPair.identifier != selfCard.publicKey.identifier {
                let keyPair = try self.localKeyStorage.retrieveKeyPair()

                try self.cloudKeyManager.store(key: keyPair.privateKey, password: password)
            }
        }
        catch CloudKeyStorageError.entryNotFound {
            let keyPair = try self.localKeyStorage.retrieveKeyPair()

            try self.cloudKeyManager.store(key: keyPair.privateKey, password: password)
        }
    }
}
