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

import XCTest
import VirgilE3Kit
import VirgilCrypto
import VirgilSDK

class VTE007_CompatibilityTests: XCTestCase {
    var config: TestConfig!
    var utils: TestUtils!
    let crypto = try! VirgilCrypto()

    override func setUp() {
        self.config = TestConfig.readFromBundle()
        self.utils = TestUtils(crypto: self.crypto, consts: self.config)
    }

    private func setUpDevice(identity: String) -> EThree {
        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        return try! EThree(identity: identity, tokenCallback: tokenCallback)
    }

    func test01_STE_45() {
        let config = self.config.Group

        let params = try! KeychainStorageParams.makeKeychainStorageParams()
        let keychainStorage = KeychainStorage(storageParams: params)
        try? keychainStorage.deleteEntry(withName: config.Identity)

        let privateKeyData = Data(base64Encoded: config.PrivateKey)!
        _ = try! keychainStorage.store(data: privateKeyData, withName: config.Identity, meta: nil)

        let ethree = self.setUpDevice(identity: config.Identity)

        let initiatorCard = try! ethree.findUser(with: config.Initiator).startSync().get()

        let groupIdData = Data(base64Encoded: config.GroupId)!
        let group = try! ethree.loadGroup(id: groupIdData, initiator: initiatorCard).startSync().get()

        XCTAssert(group.participants == Set(config.Participants))

        let decrypted = try! group.decrypt(text: config.EncryptedText, from: initiatorCard)

        XCTAssert(decrypted == config.OriginText)
    }
}
