//
// Copyright (C) 2015-2020 Virgil Security Inc.
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
@testable import VirgilE3Kit

class VTE008_AdditionalTests: XCTestCase {
    func test01__product_info_version__should_be_same_as_bundle() {
        let bundle = Bundle(identifier: "com.virgilsecurity.VirgilE3Kit")!
        let info = bundle.infoDictionary!
        let version = info["CFBundleShortVersionString"] as! String

        XCTAssert(VirgilE3Kit.ProductInfo.version == version)
    }

    func test02_STE_49__init_ethreeParams__from_valid_config__should_succeed() {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            completion("token", nil)
        }

        let bundle = Bundle(for: TestConfig.self)
        let configFileUrl = bundle.url(forResource: "EThreeValidConfig", withExtension: "plist")!

        let params = try! EThreeParams(identity: identity,
                                       tokenCallback: tokenCallback,
                                       configUrl: configFileUrl)

        XCTAssert(params.enableRatchet == false)
        XCTAssert(params.keyRotationInterval == 1_600)
        XCTAssert(params.keyPairType == .curve25519Round5Ed25519Falcon)
    }

    func test03_STE_50__init_ethreeParams__invalid_config__should_throw_error() {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            completion("token", nil)
        }

        let bundle = Bundle(for: TestConfig.self)
        let configFileUrl = bundle.url(forResource: "EThreeInvalidConfig", withExtension: "plist")!

        do {
            _ = try EThreeParams(identity: identity,
                                 tokenCallback: tokenCallback,
                                 configUrl: configFileUrl)
        } catch EThreeParamsError.unknownKeyInConfig {} catch {
            XCTFail()
        }
    }

    func test04_STE_69__init_ethreeParams__from_example_config__should_succeed() {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            completion("token", nil)
        }

        let bundle = Bundle(for: TestConfig.self)
        let configFileUrl = bundle.url(forResource: "EThreeConfig", withExtension: "plist")!

        let params = try! EThreeParams(identity: identity,
                                       tokenCallback: tokenCallback,
                                       configUrl: configFileUrl)

        XCTAssert(params.enableRatchet == false)
        XCTAssert(params.keyRotationInterval == 3_600)
    }
}
