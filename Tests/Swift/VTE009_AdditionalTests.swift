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
import XCTest
@testable import VirgilE3Kit

class VTE008_AdditionalTests: XCTestCase {

    // Note: For now there is no way to access Info.plist of lib from SPM build (https://forums.swift.org/t/add-info-plist-on-spm-bundle/40274/6)
#if !SPM_BUILD
    func test01__product_info_version__should_be_same_as_bundle() {
        let info = Bundle.module.infoDictionary!
        let version = info["CFBundleShortVersionString"] as! String

        XCTAssert(VirgilE3Kit.ProductInfo.version == version)
    }
#endif

    func test02_STE_49__init_ethreeParams__from_valid_config__should_succeed() {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            completion("token", nil)
        }

        let configFileUrl = Bundle.module.url(forResource: "EThreeValidConfig", withExtension: "plist")!

        let params = try! EThreeParams(identity: identity,
                                       tokenCallback: tokenCallback,
                                       configUrl: configFileUrl)

        XCTAssert(params.enableRatchet == false)
        XCTAssert(params.keyRotationInterval == 1_600)
        XCTAssert(params.keyPairType == .curve25519Round5Ed25519Falcon)
        XCTAssert(params.offlineInit == true)
    }

    func test03_STE_50__init_ethreeParams__invalid_config__should_throw_error() {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            completion("token", nil)
        }

        let configFileUrl = Bundle.module.url(forResource: "EThreeInvalidConfig", withExtension: "plist")!

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

        let configFileUrl = Bundle.module.url(forResource: "EThreeConfig", withExtension: "plist")!

        let params = try! EThreeParams(identity: identity,
                                       tokenCallback: tokenCallback,
                                       configUrl: configFileUrl)

        XCTAssert(params.enableRatchet == false)
        XCTAssert(params.keyRotationInterval == 3_600)
    }
    
    func test05_STE_87__init_ethree__with_initial_jwt__should_succeed() {
        let utils = TestUtils()
        
        let identity = UUID().uuidString
        let initialJwt = utils.getToken(identity: identity)

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            XCTFail()
        }

        let params = EThreeParams(initialJwt: initialJwt,
                                  tokenCallback: tokenCallback)
                                       
        let ethree = try! EThree(params: params)
        
        _ = ethree.findUser(with: ethree.identity, forceReload: true)
    }
}
