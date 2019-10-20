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
    /// Enables ratchet operations
    @objc public var enableRatchet: Bool = Defaults.enableRatchet
    /// TimeInterval of automatic rotate keys for double ratchet
    @objc public var keyRotationInterval: TimeInterval = Defaults.keyRotationInterval

    private struct Config: Decodable {
        var enableRatchet: Bool = Defaults.enableRatchet
        var keyRotationInterval: TimeInterval = Defaults.keyRotationInterval

        enum CodingKeys: String, CodingKey {
            case enableRatchet
            case keyRotationInterval
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)

            if let enableRatchet = try? container.decode(Bool.self, forKey: .enableRatchet) {
                self.enableRatchet = enableRatchet
            }

            if let keyRotationInterval = try? container.decode(TimeInterval.self, forKey: .keyRotationInterval) {
                self.keyRotationInterval = keyRotationInterval
            }
        }

        static func deserialize(from url: URL) throws -> Config {
            guard let dictionary = NSDictionary(contentsOf: url),
                let keys = dictionary.allKeys as? [String]  else {
                    throw EThreeParamsError.invalidPlistFile
            }

            try keys.forEach {
                guard CodingKeys(rawValue: $0) != nil else {
                    throw EThreeParamsError.unknownKeyInConfig
                }
            }

            let data = try Data(contentsOf: url)

            return try PropertyListDecoder().decode(Config.self, from: data)
        }
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
        let config = try Config.deserialize(from: configUrl)

        self.init(identity: identity, tokenCallback: tokenCallback)

        self.enableRatchet = config.enableRatchet
        self.keyRotationInterval = config.keyRotationInterval
    }

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
