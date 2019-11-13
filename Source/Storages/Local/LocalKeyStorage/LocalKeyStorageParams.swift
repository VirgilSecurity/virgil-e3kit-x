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

internal class LocalKeyStorageParams {
    internal let identity: String
    internal let crypto: VirgilCrypto
    internal let keychain: KeychainStorage
    internal let options: KeychainQueryOptions

#if os(iOS)
    internal var biometricProtection: Bool = Defaults.biometricProtection {
        didSet {
            self.options.biometricallyProtected = biometricProtection
        }
    }

    /// Access time during which key is cached in RAM. If nil, key won't be cleaned from RAM using timer. Default - nil
    internal var accessTime: TimeInterval?
    /// Cleans private key from RAM on entering background. Default - false
    internal var cleanOnEnterBackground: Bool = Defaults.cleanKeyCacheOnEnterBackground
    /// Requests private key on entering foreground. Default - false
    internal var requestOnEnterForeground: Bool = Defaults.requestKeyOnEnterForeground
    /// Error callback for errors during entering foreground. Default - nil
    internal var enterForegroundErrorCallback: ProtectedKeyOptions.ErrorCallback? = nil
#endif

    internal init(identity: String, crypto: VirgilCrypto, storageParams: KeychainStorageParams?) throws {
        self.identity = identity
        self.crypto = crypto

        self.options = KeychainQueryOptions()

        let storageParams = try storageParams ?? KeychainStorageParams.makeKeychainStorageParams()
        self.keychain = KeychainStorage(storageParams: storageParams)
    }
}
