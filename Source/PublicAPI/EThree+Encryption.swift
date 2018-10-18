//
// Copyright (C) 2015-2018 Virgil Security Inc.
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
import VirgilCryptoApiImpl

extension EThree {
    public func encrypt(_ text: String, for recipientKeys: [VirgilPublicKey]) throws -> String {
        guard let data = text.data(using: .utf8) else {
            throw EThreeError.strToDataFailed
        }
        guard !recipientKeys.isEmpty, let selfKeyPair = self.identityKeyPair else {
            throw EThreeError.missingKeys
        }
        let publicKeys = recipientKeys + [selfKeyPair.publicKey]
        let encryptedData = try self.crypto.signThenEncrypt(data, with: selfKeyPair.privateKey, for: publicKeys)

        return encryptedData.base64EncodedString()
    }

    public func decrypt(_ encrypted: String, from senderKeys: [VirgilPublicKey]) throws -> String {
        guard let data = Data(base64Encoded: encrypted) else {
            throw EThreeError.strToDataFailed
        }
        guard !senderKeys.isEmpty, let selfKeyPair = self.identityKeyPair else {
            throw EThreeError.missingKeys
        }
        let publicKeys = senderKeys + [selfKeyPair.publicKey]

        let decryptedData = try self.crypto.decryptThenVerify(data, with: selfKeyPair.privateKey,
                                                              usingOneOf: publicKeys)
        guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
            throw EThreeError.strFromDataFailed
        }

        return decryptedString
    }

    public func lookupPublicKeys(of identities: [String], completion: @escaping ([VirgilPublicKey], [Error]) -> ()) {
        guard !identities.isEmpty else {
            completion([], [])
            return
        }

        let group = DispatchGroup()
        var result: [VirgilPublicKey] = []
        var errors: [Error] = []

        for identity in identities {
            group.enter()
            self.cardManager.searchCards(identity: identity) { cards, error in
                if let error = error {
                    errors.append(error)
                    return
                }
                guard let publicKey = cards?.first?.publicKey,
                    let virgilPublicKey = publicKey as? VirgilPublicKey else {
                        errors.append(EThreeError.keyIsNotVirgil)
                        return
                }

                result.append(virgilPublicKey)

                defer { group.leave() }
            }
        }

        group.notify(queue: .main) {
            completion(result, errors)
        }
    }
}
