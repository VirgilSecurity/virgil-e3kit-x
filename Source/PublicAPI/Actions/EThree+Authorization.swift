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

// MARK: - Extension with authorization operations
extension EThree {

    private func isBackedUp() throws -> Bool {
        return true
    }

    private enum EThreeUnfinishedFlowError: Error {

    }

    private func askUserToFinishFlowOnOriginDevice(completion: @escaping (Bool) throws -> Void) throws {
        try completion(true)
    }

    private func askUserPassword(completion: @escaping (String) throws -> Void) throws {
        try completion("password")
    }

    open func isLoggedIn() throws -> Bool {
        return try self.hasLocalPrivateKey() && self.isBackedUp()
    }

    open func appFlow(ethree: EThree) throws {
        if try !ethree.isLoggedIn() {

            try self.askUserPassword { password in
                do {
                    try ethree.authFlow(password: password)
                }
                catch let error as EThreeUnfinishedFlowError {
                    Log.error(error.localizedDescription)

                    try self.askUserToFinishFlowOnOriginDevice { userLostDevice in
                        if userLostDevice {
                            try self.rotateFlow(password: password)
                        }
                    }
                }
            }

        }
    }

    open func authFlow(password: String) throws {
        // 1. What if user was registered, but failed backup key - proper error on restorePrivateKey - propose rotate flow in UI
        // 2. What if user rotated key before this flow - cleanUp before/after flow. Run flow again. Should be managed by developer.
        // 3. What if key was rotated, but keyknox wasn't reseted - add id check on restorePrivateKey - propose rotate flow in UI
        // 4. What if key was rotated, reseted, but not backed up - proper error on restorePrivateKey - propose rotate flow in UI

        if try self.hasLocalPrivateKey() {
            if try !self.isBackedUp() {                                         // Checks Local Key mark
                try self.backupPrivateKey(password: password).startSync().get()
            }
        } else {
            do {
                try self.register().startSync().get()                            // Local Key marked as not backed up

                try self.backupPrivateKey(password: password).startSync().get()  // Local Key marked as backed up

            } catch EThreeError.userIsAlreadyRegistered {
                try self.restorePrivateKey(password: password).startSync().get() // Local Key marked as backed up
            }
        }
    }

    /// Rotate flow should be used only if user confirmed he lost access to original device, private key
    open func rotateFlow(password: String) throws {
        try self.cleanUp()

        try self.rotatePrivateKey().startSync().get()                           // Local Key marked as not backed up

        try self.resetPrivateKeyBackup().startSync().get()

        try self.backupPrivateKey(password: password).startSync().get()         // Local Key marked as backed up
    }

    open func proposeUserRotate() throws -> GenericOperation<Bool> {
        return CallbackOperation { _, _ in }
    }

    open func getTokenFromServer() throws -> String {
        return "dummy"
    }

    // TODO: fix double cards issue
    // Make token callback throwable?













    /// Publishes Card on Virgil Cards Service and saves Private Key in local storage
    ///
    /// - Parameter keyPair: `VirgilKeyPair` to publish Card with. Will generate if not specified
    /// - Returns: CallbackOperation<Void>
    open func register(with keyPair: VirgilKeyPair? = nil) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    guard try !self.localKeyStorage.exists() else {
                        throw EThreeError.privateKeyExists
                    }

                    // TODO: Change to findUser
                    let cards = try self.cardManager.searchCards(identities: [self.identity]).startSync().get()

                    guard cards.isEmpty else {
                        throw EThreeError.userIsAlreadyRegistered
                    }

                    try self.publishCardThenSaveLocal(keyPair: keyPair)

                    completion((), nil)
                } catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Generates new Private Key, publishes new Card to replace the current one on Virgil Cards Service
    /// and saves new Private Key in local storage
    ///
    /// - Returns: CallbackOperation<Void>
    open func rotatePrivateKey() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    guard try !self.localKeyStorage.exists() else {
                        throw EThreeError.privateKeyExists
                    }

                    let cards = try self.cardManager.searchCards(identities: [self.identity]).startSync().get()

                    guard let card = cards.first else {
                        throw EThreeError.userIsNotRegistered
                    }

                    try self.publishCardThenSaveLocal(previousCardId: card.identifier)

                    completion((), nil)
                } catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Revokes Card from Virgil Cards Service, deletes Private Key from local storage
    ///
    /// - Returns: CallbackOperation<Void>
    open func unregister() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            self.queue.async {
                do {
                    let cards = try self.cardManager.searchCards(identities: [self.identity]).startSync().get()

                    guard let card = cards.first else {
                        throw EThreeError.userIsNotRegistered
                    }

                    try self.cardManager.revokeCard(withId: card.identifier).startSync().get()

                    try self.localKeyStorage.delete()

                    try self.privateKeyDeleted()

                    completion((), nil)
                } catch {
                    completion(nil, error)
                }
            }
        }
    }

    /// Checks existance of private key in keychain storage
    ///
    /// - Returns: true if private key exists in keychain storage
    /// - Throws: KeychainStorageError
    open func hasLocalPrivateKey() throws -> Bool {
        return try self.localKeyStorage.exists()
    }

    /// Deletes Private Key from local storage, cleand local cards storage
    ///
    /// - Throws: KeychainStorageError
    @objc open func cleanUp() throws {
        try self.localKeyStorage.delete()

        try self.privateKeyDeleted()
    }
}
