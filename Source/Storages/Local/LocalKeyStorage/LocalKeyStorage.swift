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

import VirgilCrypto
import VirgilSDK

internal class LocalKeyStorage {
    internal let identity: String
    internal let crypto: VirgilCrypto
    internal var keyWrapper: PrivateKeyWrapper

    private let keychain: KeychainStorage
    private let options: KeychainQueryOptions

    internal init(params: LocalKeyStorageParams) throws {
        self.identity = params.identity
        self.crypto = params.crypto
        self.keychain = params.keychain
        self.options = params.options

        let options = ProtectedKeyOptions(keychainStorage: params.keychain)
    #if os(iOS)
        options.biometricallyProtected = params.biometricProtection
        options.accessTime = params.accessTime
        options.cleanOnEnterBackground = params.cleanOnEnterBackground
        options.requestOnEnterForeground = params.requestOnEnterForeground
        options.enterForegroundErrorCallback = params.enterForegroundErrorCallback
    #endif

        let key = try EThreeProtectedKey(keyName: self.identity, options: options)
        self.keyWrapper = PrivateKeyWrapper(protectedKey: key, crypto: self.crypto)
    }

    internal func store(data: Data) throws {
        _ = try self.keychain.store(data: data,
                                    withName: self.identity,
                                    meta: nil,
                                    queryOptions: self.options)

        self.keyWrapper.resetCache()
    }

    internal func exists() throws -> Bool {
        return try self.keychain.existsEntry(withName: self.identity, queryOptions: self.options)
    }

    internal func delete() throws {
        try self.keychain.deleteEntry(withName: self.identity, queryOptions: self.options)

        self.keyWrapper.resetCache()
    }
}
