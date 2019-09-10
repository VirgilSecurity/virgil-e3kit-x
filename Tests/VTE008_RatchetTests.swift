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

class REThreeTests: XCTestCase {
    let utils = TestUtils()

    private func setUpDevice() throws -> (REThree, Card) {
        let identity = UUID().uuidString

        let tokenCallback: EThreeBase.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let ethree = try EThree(identity: identity, tokenCallback: tokenCallback)
        let rethree = try REThree.initialize(ethreeBase: ethree).startSync().get()

        try rethree.register().startSync().get()

        let card = try rethree.findUser(with: identity).startSync().get()

        return (rethree, card)
    }

    func test_1_register() {
        do {
            _ = try self.setUpDevice()
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test_2_encrypt_decrypt() {
        do {
            let (rethree1, card1) = try self.setUpDevice()
            let (rethree2, card2) = try self.setUpDevice()

            try rethree1.startChat(with: rethree2.identity).startSync().get()

            let message1 = "Hello, \(rethree2.identity)"
            let encrypted1 = try rethree1.encrypt(text: message1, for: card2)

            let decrypted1 = try rethree2.decrypt(text: encrypted1, from: card1)

            XCTAssert(message1 == decrypted1)

            let message2 = "Hello back, \(rethree1.identity)"
            let encrypted2 = try rethree2.encrypt(text: message2, for: card1)

            let decrypted2 = try rethree1.decrypt(text: encrypted2, from: card2)

            XCTAssert(message2 == decrypted2)
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}

