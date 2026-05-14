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
import VirgilCrypto
import VirgilSDK
import XCTest

@testable import VirgilE3Kit

class VTE004_NamedKeyBackupTests: XCTestCase {
    let utils = TestUtils()

    func test01_STE_15__namedBackup__lifecycle() {
        do {
            let password = UUID().uuidString
            let keyName = UUID().uuidString

            let ethree = try self.utils.setupEThree(
                identity: UUID().uuidString,
                enableRatchet: false,
                keyRotationInterval: 0
            )

            do {
                try ethree.backupPrivateKey(password: password, keyName: keyName).startSync().get()
                XCTFail("Expected missingPrivateKey — no key stored yet")
            } catch EThreeError.missingPrivateKey {}

            try ethree.register().startSync().get()

            try ethree.backupPrivateKey(password: password, keyName: keyName).startSync().get()

            sleep(2)

            do {
                try ethree.backupPrivateKey(password: password, keyName: keyName).startSync().get()
                XCTFail("Expected error — named backup entry already exists")
            } catch {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test02_STE_16__namedRestore__lifecycle() {
        do {
            let password = UUID().uuidString
            let keyName = UUID().uuidString
            let ethree = try self.utils.setupDevice()

            try ethree.backupPrivateKey(password: password, keyName: keyName).startSync().get()

            sleep(2)

            try ethree.cleanUp()

            try ethree.restorePrivateKey(password: password, keyName: keyName).startSync().get()
            XCTAssert(try ethree.hasLocalPrivateKey())

            sleep(2)

            do {
                try ethree.restorePrivateKey(password: password, keyName: keyName).startSync().get()
                XCTFail("Expected privateKeyExists")
            } catch EThreeError.privateKeyExists {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test03_STE_16_1__namedAndDefaultRestore__coexist() {
        do {
            let password = UUID().uuidString
            let keyName = UUID().uuidString
            let ethree = try self.utils.setupDevice()

            try ethree.backupPrivateKey(password: password).startSync().get()

            sleep(2)

            try ethree.backupPrivateKey(password: password, keyName: keyName).startSync().get()

            sleep(2)

            try ethree.cleanUp()

            try ethree.restorePrivateKey(password: password, keyName: keyName).startSync().get()
            XCTAssert(try ethree.hasLocalPrivateKey())

            try ethree.cleanUp()

            try ethree.restorePrivateKey(password: password).startSync().get()
            XCTAssert(try ethree.hasLocalPrivateKey())
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test04_STE_17__namedChangePassword__should_update_backup_key() {
        do {
            let password = UUID().uuidString
            let newPassword = UUID().uuidString
            let keyName = UUID().uuidString
            let ethree = try self.utils.setupDevice()

            try ethree.backupPrivateKey(password: password, keyName: keyName).startSync().get()

            sleep(2)

            do {
                try ethree.changePassword(from: "WrongPassword", to: newPassword, keyName: keyName).startSync().get()
                XCTFail("Expected error with wrong old password")
            } catch {}

            sleep(2)

            try ethree.changePassword(from: password, to: newPassword, keyName: keyName).startSync().get()

            sleep(2)

            try ethree.cleanUp()

            do {
                try ethree.restorePrivateKey(password: password, keyName: keyName).startSync().get()
                XCTFail("Expected wrongPassword with old password")
            } catch EThreeError.wrongPassword {}

            sleep(2)

            try ethree.restorePrivateKey(password: newPassword, keyName: keyName).startSync().get()
            XCTAssert(try ethree.hasLocalPrivateKey())
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }

    func test05_STE_18__namedReset__should_delete_backup() {
        do {
            let password = UUID().uuidString
            let keyName = UUID().uuidString
            let ethree = try self.utils.setupDevice()

            try ethree.backupPrivateKey(password: password, keyName: keyName).startSync().get()

            try ethree.resetPrivateKeyBackup(keyName: keyName).startSync().get()

            sleep(2)

            try ethree.cleanUp()

            do {
                try ethree.restorePrivateKey(password: password, keyName: keyName).startSync().get()
                XCTFail("Expected error — named backup was reset")
            } catch {}
        } catch {
            print(error.localizedDescription)
            XCTFail()
        }
    }
}
