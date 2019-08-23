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

internal class OnFirstNeedKeyStorage: OnlyOnUseKeyStorage {
    internal var cachedKeyPair: CachedKeyPair?
    internal var cacheLifeTime: TimeInterval = 1_800

    internal struct CachedKeyPair {
        internal let value: VirgilKeyPair
        internal let expiresAt: Date

        internal func isExpired() -> Bool {
            return Date() > self.expiresAt
        }
    }

    internal required init(params: LocalKeyStorageParams) throws {
        try super.init(params: params)

        if let cacheLifeTime = params.cacheLifeTime {
            self.cacheLifeTime = cacheLifeTime
        }
    }

    override internal func store(data: Data) throws {
        try super.store(data: data)

        let keyPair = try self.crypto.importPrivateKey(from: data)

        self.cache(keyPair)
    }

    override internal func getKeyPair() throws -> VirgilKeyPair {
        guard let cachedKeyPair = self.cachedKeyPair, !cachedKeyPair.isExpired() else {
            let keyPair = try super.getKeyPair()

            self.cache(keyPair)

            return keyPair
        }

        return cachedKeyPair.value
    }

    override internal func delete() throws {
        try super.delete()

        self.cleanCache()
    }

    internal func cleanCache() {
        self.cachedKeyPair = nil
    }

    internal func cache(_ keyPair: VirgilKeyPair) {
        let expiresAt = Date() + self.cacheLifeTime

        self.cachedKeyPair = CachedKeyPair(value: keyPair, expiresAt: expiresAt)
    }
}
