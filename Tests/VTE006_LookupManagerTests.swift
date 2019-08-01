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

class VTE006_LookupManagerTests: XCTestCase {
    var testUtils: TestUtils!
    let crypto = try! VirgilCrypto()

    override func setUp() {
        let consts = TestConfig.readFromBundle()

        self.testUtils = TestUtils(crypto: self.crypto, consts: consts)
    }

    private func setUpDevice() -> (EThree) {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.testUtils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let ethree = try! EThree.initialize(tokenCallback: tokenCallback).startSync().get()

        try! ethree.register().startSync().get()

        return ethree
    }

    func test_1() {
        let ethree1 = self.setUpDevice()
        let ethree2 = self.setUpDevice()

        XCTAssert(ethree1.lookupCachedCard(of: ethree2.identity) == nil)

        let card2 = try! ethree1.lookupCard(of: ethree2.identity).startSync().get()

        let cachedCard2 = ethree1.lookupCachedCard(of: ethree2.identity)

        XCTAssert(cachedCard2?.identifier == card2.identifier)
    }
}
