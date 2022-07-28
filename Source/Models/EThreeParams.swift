//
// Copyright (C) 2015-2021 Virgil Security Inc.
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

import Foundation
import VirgilSDK
import VirgilSDKPythia
import VirgilSDKRatchet
import VirgilCrypto

/// Contains parameters for initializing EThree
/// - Tag: EThreeParams
@objc(VTEEThreeParams) public class EThreeParams: NSObject {
    /// Identity of user
    @objc public let identity: String
    /// Callback to get Virgil access token
    @objc public let tokenCallback: EThree.RenewJwtCallback
    /// [ChangedKeyDelegate](x-source-tag://ChangedKeyDelegate) to notify changing of User's keys
    @objc public weak var changedKeyDelegate: ChangedKeyDelegate? = nil
    /// AppGroup
    @objc public var appGroup: String? = nil
    /// `KeychainStorageParams` with specific parameters
    @objc public var storageParams: KeychainStorageParams? = nil
    /// Default key pair type
    @objc public var keyPairType: KeyPairType = Defaults.keyPairType
    /// Enables ratchet operations
    @objc public var enableRatchet: Bool = Defaults.enableRatchet
    /// Enables ratchet pqc
    @objc public var enableRatchetPqc: Bool = Defaults.enableRatchetPqc
    /// Offline init
    @objc public var offlineInit: Bool = Defaults.offlineInit
    /// TimeInterval of automatic rotate keys for double ratchet
    @objc public var keyRotationInterval: TimeInterval = Defaults.keyRotationInterval
    /// Service urls
    @objc public var serviceUrls: ServiceUrls
    /// Initial Jwt
    @objc public var initialJwt: Jwt? = nil

    /// Service urls
    @objc(VTEServiceUrls) public class ServiceUrls: NSObject {
        /// Card service URL
        @objc public var cardServiceUrl: URL

        /// Pythia service URL
        @objc public var pythiaServiceUrl: URL

        /// Keyknox service URL
        @objc public var keyknoxServiceUrl: URL

        /// Ratchet service URL
        @objc public var ratchetServiceUrl: URL

        /// Init
        /// - Parameters:
        ///   - cardServiceUrl: Card service URL
        ///   - pythiaServiceUrl: Pythia service URL
        ///   - keyknoxServiceUrl: Keyknox service URL
        ///   - ratchetServiceUrl: Ratchet service URL
        @objc public init(cardServiceUrl: URL,
                          pythiaServiceUrl: URL,
                          keyknoxServiceUrl: URL,
                          ratchetServiceUrl: URL) {
            self.cardServiceUrl = cardServiceUrl
            self.pythiaServiceUrl = pythiaServiceUrl
            self.keyknoxServiceUrl = keyknoxServiceUrl
            self.ratchetServiceUrl = ratchetServiceUrl
        }
    }

    /// NOTE: Use this only while working with environments other than Virgil production
    @objc public var overrideVirgilPublicKey: String? = nil

    private struct Config: Decodable {
        var keyPairType: KeyPairType = Defaults.keyPairType
        var enableRatchet: Bool = Defaults.enableRatchet
        var enableRatchetPqc: Bool = Defaults.enableRatchetPqc
        var offlineInit: Bool = Defaults.offlineInit
        var keyRotationInterval: TimeInterval = Defaults.keyRotationInterval

        enum CodingKeys: String, CodingKey {
            case keyPairType
            case enableRatchet
            case enableRatchetPqc
            case offlineInit
            case keyRotationInterval
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)

            do {
                let keyPairTypeStr = try container.decode(String.self, forKey: .keyPairType)
                self.keyPairType = try KeyPairType(from: keyPairTypeStr)
            }
            catch DecodingError.keyNotFound(_, _) { }
            catch DecodingError.valueNotFound(_, _) { }

            do {
                self.enableRatchet = try container.decode(Bool.self, forKey: .enableRatchet)
            }
            catch DecodingError.keyNotFound(_, _) { }
            catch DecodingError.valueNotFound(_, _) { }

            do {
                self.enableRatchetPqc = try container.decode(Bool.self, forKey: .enableRatchetPqc)
            }
            catch DecodingError.keyNotFound(_, _) { }
            catch DecodingError.valueNotFound(_, _) { }

            do {
                self.offlineInit = try container.decode(Bool.self, forKey: .offlineInit)
            }
            catch DecodingError.keyNotFound(_, _) { }
            catch DecodingError.valueNotFound(_, _) { }

            do {
                self.keyRotationInterval = try container.decode(TimeInterval.self, forKey: .keyRotationInterval)
            }
            catch DecodingError.keyNotFound(_, _) { }
            catch DecodingError.valueNotFound(_, _) { }
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

    @objc public convenience init(initialJwt: Jwt,
                                  tokenCallback: @escaping EThree.RenewJwtCallback,
                                  configUrl: URL) throws {
         try self.init(identity: initialJwt.identity(),
                       tokenCallback: tokenCallback,
                       configUrl: configUrl)

         self.initialJwt = initialJwt
     }

     @objc public convenience init(initialJwt: Jwt,
                                   tokenCallback: @escaping EThree.RenewJwtCallback) {
         self.init(identity: initialJwt.identity(), tokenCallback: tokenCallback)

         self.initialJwt = initialJwt
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

        self.keyPairType = config.keyPairType
        self.enableRatchet = config.enableRatchet
        self.enableRatchetPqc = config.enableRatchetPqc
        self.offlineInit = config.offlineInit
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
        self.serviceUrls = ServiceUrls(cardServiceUrl: CardClient.defaultURL,
                                       pythiaServiceUrl: PythiaClient.defaultURL,
                                       keyknoxServiceUrl: KeyknoxClient.defaultURL,
                                       ratchetServiceUrl: RatchetClient.defaultURL)

        super.init()
    }
}
