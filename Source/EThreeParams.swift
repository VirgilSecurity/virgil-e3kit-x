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

/// Contains parameters for initializing EThree
/// - Tag: EThreeParams
@objc(VTEEThreeParams) public class EThreeParams: NSObject {
    /// Identity of user
    @objc public let identity: String
    /// Callback to get Virgil access token
    @objc public let tokenCallback: EThree.RenewJwtCallback
    /// [ChangedKeyDelegate](x-source-tag://ChangedKeyDelegate) to notify changing of User's keys
    @objc public weak var changedKeyDelegate: ChangedKeyDelegate? = nil
    /// `KeychainStorageParams` with specific parameters
    @objc public var storageParams: KeychainStorageParams? = nil

#if os(iOS)
    /// Will use biometric or passcode protection of key if true
    @objc public var biometricProtection: Bool = Defaults.biometricProtection
    /// User promt for UI
    @objc public var biometricPromt: String? = Defaults.biometricPromt
    /// Defines behaviour of key load
    @objc public var loadKeyStrategy: LoadKeyStrategy = Defaults.loadKeyStrategy
    /// Defines how long cached key can be used before retrieved again
    @objc public var keyCacheLifeTime: TimeInterval = Defaults.keyCacheLifeTime

    private struct BiometryConfig: Decodable {
        var biometricProtection: Bool = Defaults.biometricProtection
        var biometricPromt: String? = Defaults.biometricPromt
        var loadKeyStrategy: LoadKeyStrategy = Defaults.loadKeyStrategy
        var keyCacheLifeTime: TimeInterval = Defaults.keyCacheLifeTime
    }

    /// Initializer with parameters from config plist file
    ///
    /// - Parameters:
    ///   - identity: Identity of user
    ///   - tokenCallback: Callback to get Virgil access token
    ///   - configUrl: URL of config file
    /// - Throws: corresponding error
    @objc public convenience init(identity: String,
                                  tokenCallback: @escaping EThree.RenewJwtCallback,
                                  configUrl: URL) throws {
        let data = try Data(contentsOf: configUrl)

        let config = try PropertyListDecoder().decode(BiometryConfig.self, from: data)

        self.init(identity: identity, tokenCallback: tokenCallback)

        self.biometricProtection = config.biometricProtection
        self.biometricPromt = config.biometricPromt
        self.loadKeyStrategy = config.loadKeyStrategy
        self.keyCacheLifeTime = config.keyCacheLifeTime
    }
#endif

    /// Initializer
    ///
    /// - Parameters:
    ///   - identity: Identity of user
    ///   - tokenCallback: Callback to get Virgil access token
    @objc public init(identity: String,
                      tokenCallback: @escaping EThree.RenewJwtCallback) {
        self.identity = identity
        self.tokenCallback = tokenCallback

        super.init()
    }
}
