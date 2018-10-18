//
//  EThree.swift
//  VirgilE3Kit
//
//  Created by Eugen Pivovarov on 10/18/18.
//

import Foundation
import VirgilSDK
import VirgilCryptoApiImpl

public enum EThreeError: Int, Error {
    case gettingJwtFailed = 1
    case verifierInitFailed = 2
}

open class EThree {
    public typealias JwtStringCallback = (String?, Error?) -> Void
    public typealias RenewJwtCallback = (@escaping JwtStringCallback) -> Void

    public let identity: String
    public let crypto: VirgilCrypto
    public let keychainStorage: KeychainStorage
    public let privateKeyExporter: VirgilPrivateKeyExporter
    public let cardManager: CardManager

    struct IdentityKeyPair {
        let privateKey: VirgilPrivateKey
        let publicKey: VirgilPublicKey
        let isPublished: Bool
    }

    enum Keys: String {
        case isPublished
    }

    var identityKeyPair: IdentityKeyPair? {
        get {
            guard let keyEntry = try? self.keychainStorage.retrieveEntry(withName: self.identity),
                let key = try? self.privateKeyExporter.importPrivateKey(from: keyEntry.data),
                let meta = keyEntry.meta,
                let isPublishedString = meta[Keys.isPublished.rawValue],
                let identityKey = key as? VirgilPrivateKey,
                let publicKey = try? self.crypto.extractPublicKey(from: identityKey) else {
                    return nil
            }
            let isPublished = NSString(string: isPublishedString).boolValue

            return IdentityKeyPair(privateKey: identityKey, publicKey: publicKey, isPublished: isPublished)
        }
    }

    public static func initialize(tokenCallback: @escaping RenewJwtCallback, completion: @escaping (EThree?, Error?) -> ()) {
        let renewTokenCallback: CachingJwtProvider.RenewJwtCallback = { _, completion in
            tokenCallback(completion)
        }

        let accessTokenProvider = CachingJwtProvider(renewTokenCallback: renewTokenCallback)
        let tokenContext = TokenContext(service: "cards", operation: "publish")
        accessTokenProvider.getToken(with: tokenContext) { token, error in
            guard let identity = token?.identity(), error == nil else {
                completion(nil, EThreeError.gettingJwtFailed)
                return
            }
            do {
                let cardCrypto = VirgilCardCrypto()
                guard let verifier = VirgilCardVerifier(cardCrypto: cardCrypto) else {
                    completion(nil, EThreeError.verifierInitFailed)
                    return
                }
                let params = CardManagerParams(cardCrypto: cardCrypto,
                                               accessTokenProvider: accessTokenProvider,
                                               cardVerifier: verifier)
                let cardManager = CardManager(params: params)

                let ethree = try EThree(identity: identity, cardManager: cardManager)
                completion(ethree, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    private init(identity: String, cardManager: CardManager) throws {
        self.identity = identity
        self.crypto = VirgilCrypto()
        let keychainStorageParams = try KeychainStorageParams.makeKeychainStorageParams()
        self.keychainStorage = KeychainStorage(storageParams: keychainStorageParams)
        self.privateKeyExporter = VirgilPrivateKeyExporter()
        self.cardManager = cardManager
    }
}
