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

class VTE007_Benchmarks: XCTestCase {
    let utils = TestUtils()

    private let toEncrypt = "this string will be encrypted".data(using: .utf8)!

    private func measure(title: String,
                         maxTime: Int?,
                         invocationCount: UInt64 = 1000,
                         block: () throws -> Void) throws {
        var sum: UInt64 = 0

        print()
        print("Measurement of \(title)")

        for _ in 1...invocationCount {
            let start = DispatchTime.now()
            try block()
            let end = DispatchTime.now()

            let elapsed = end.uptimeNanoseconds - start.uptimeNanoseconds

            sum += elapsed
        }

        let average = sum / invocationCount

        print("Average: \(average) ns")
        print()

        if let maxTime = maxTime {
            XCTAssert(maxTime > average)
        }
    }

    private func setUpDevice(with keyPair: VirgilKeyPair? = nil) throws -> EThree {
        let identity = UUID().uuidString

        let tokenCallback: EThree.RenewJwtCallback = { completion in
            let token = self.utils.getTokenString(identity: identity)

            completion(token, nil)
        }

        let ethree = try EThree(identity: identity, tokenCallback: tokenCallback)

        try ethree.register(with: keyPair).startSync().get()

        return ethree
    }

    func test01_findUser_encrypt() {
        do {
            for keyType: KeyPairType in [.ed25519, .secp256r1] {
                let aliceKeyPair = try self.utils.crypto.generateKeyPair(ofType: keyType)
                let bobKeyPair = try self.utils.crypto.generateKeyPair(ofType: keyType)

                let alice = try self.setUpDevice(with: aliceKeyPair)
                let bob = try self.setUpDevice(with: bobKeyPair)

                _ = try alice.findUser(with: bob.identity).startSync().get()

                let block = {
                    let bobCard = alice.findCachedUser(with: bob.identity)!

                    _ = try alice.signThenEncrypt(data: self.toEncrypt, for: bobCard)
                }

                try self.measure(title: "encryption with \(keyType.rawStrValue)", maxTime: 100_000_000, block: block)
            }
        } catch {
            print("Test faield with error: \(error.localizedDescription)")
        }
    }

    func test02_findUser_decrypt() {
        do {
            for keyType: KeyPairType in [.ed25519, .secp256r1] {
                let aliceKeyPair = try self.utils.crypto.generateKeyPair(ofType: keyType)
                let bobKeyPair = try self.utils.crypto.generateKeyPair(ofType: keyType)

                let alice = try self.setUpDevice(with: aliceKeyPair)
                let bob = try self.setUpDevice(with: bobKeyPair)

                let bobCard = try alice.findUser(with: bob.identity).startSync().get()
                let encrypted = try alice.signThenEncrypt(data: self.toEncrypt, for: bobCard)

                _ = try bob.findUser(with: alice.identity).startSync().get()

                let block = {
                    let aliceCard = bob.findCachedUser(with: alice.identity)!

                    _ = try bob.decryptThenVerify(data: encrypted, from: aliceCard)
                }

                try self.measure(title: "decryption with \(keyType.rawStrValue)", maxTime: 100_000_000, block: block)
            }
        } catch {
            print("Test faield with error: \(error.localizedDescription)")
        }
    }

    func test03__group_update() {
        do {
            let ethree1 = try self.setUpDevice()
            let ethree2 = try self.setUpDevice()
            let ethree3 = try self.setUpDevice()

            let identifier = UUID().uuidString

            let result = try ethree1.findUsers(with: [ethree2.identity, ethree3.identity]).startSync().get()
            let group1 = try ethree1.createGroup(id: identifier, with: result).startSync().get()

            let card1 = try ethree2.findUser(with: ethree1.identity).startSync().get()
            let card3 = try ethree1.findUser(with: ethree3.identity).startSync().get()

            let group2 = try ethree2.loadGroup(id: identifier, initiator: card1).startSync().get()

            for i in 0..<20 {
                try group1.remove(participant: card3).startSync().get()
                try group1.add(participant: card3).startSync().get()

                let block = {
                    try group2.update().startSync().get()
                }

                try self.measure(title: "Update group with \(i) tickets", maxTime: 1_000_000_000, invocationCount: 1, block: block)
            }
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}

private extension KeyPairType {
    var rawStrValue: String {
        switch self {
        case .ed25519:
            return "ed25519"
        case .curve25519:
            return "curve25519"
        case .secp256r1:
            return "secp256r1"
        case .rsa4096:
            return "rsa4096"
        default:
            return "Unknown key type"
        }
    }
}

