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

#import "VTETestBase.h"

@interface VTE003_KeyBackupTests : VTETestBase

@end

@implementation VTE003_KeyBackupTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)test01_STE_15 {
    XCTestExpectation *ex = [self expectationWithDescription:@"BackupPrivateKey tests"];

    [self.eThree backupPrivateKeyWithPassword:self.password completion:^(NSError *error) {
        XCTAssert(error.code == VTEEThreeErrorMissingPrivateKey);

        sleep(2);

        NSError *err;
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
        NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey error:&err];
        VSSKeychainEntry *entry = [self.keychainStorage storeWithData:data
                                                             withName:self.eThree.identity
                                                                 meta:nil
                                                         queryOptions:nil
                                                                error:&err];
        XCTAssert(entry != nil && err == nil);

        [self.eThree backupPrivateKeyWithPassword:self.password completion:^(NSError *error) {
            XCTAssert(error == nil);

            sleep(2);

            __weak typeof(self) weakSelf = self;
            [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password keychainStorage:self.keychainStorage identity:self.eThree.identity completion:^(VSSSyncKeyStorage *syncKeyStorage, NSError *error) {
                XCTAssert(error == nil);

                NSError *err;
                VSSKeychainEntry *syncEntry = [syncKeyStorage retrieveEntryWithName:self.eThree.identity error:&err];
                XCTAssert(err == nil && syncEntry != nil);
                XCTAssert([syncEntry.data isEqualToData:data]);

                sleep(2);

                [self.eThree backupPrivateKeyWithPassword:self.password completion:^(NSError *error) {
                    XCTAssert(error != nil);

                    [ex fulfill];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:10000 handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test02_STE_16 {
    XCTestExpectation *ex = [self expectationWithDescription:@"RestorePrivateKey tests"];

    NSError *err;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
    NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey error:&err];

    VSSCard *card __unused = [self.utils publishCardWithIdentity:self.eThree.identity previousCardId:nil];

    __weak typeof(self) weakSelf = self;
    [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password keychainStorage:self.keychainStorage identity:self.eThree.identity completion:^(VSSSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        [syncKeyStorage storeEntryWithName:self.eThree.identity data:data meta:nil completion:^(VSSKeychainEntry *entry, NSError *error) {
            XCTAssert(error == nil);

            sleep(2);

            [self.eThree restorePrivateKeyWithPassword:@"Wrong password" completion:^(NSError *error) {
                XCTAssert(error.code == VTEEThreeErrorWrongPassword);

                sleep(2);

                [self.eThree restorePrivateKeyWithPassword:self.password completion:^(NSError *error) {
                    XCTAssert(error == nil);

                    NSError *err;
                    VSSKeychainEntry *retrievedEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity
                                                                                      queryOptions:nil
                                                                                             error:&err];
                    XCTAssert(retrievedEntry != nil && err == nil);
                    XCTAssert([retrievedEntry.data isEqualToData:data]);

                    sleep(2);

                    [self.eThree restorePrivateKeyWithPassword:self.password completion:^(NSError *error) {
                        XCTAssert(error != nil);

                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test03_STE_17 {
    XCTestExpectation *ex = [self expectationWithDescription:@"ChangePrivateKeyPassword tests"];

    NSError *err;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
    NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey error:&err];

    VSSCard *card __unused = [self.utils publishCardWithIdentity:self.eThree.identity previousCardId:nil];
    
    __weak typeof(self) weakSelf = self;
    [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password keychainStorage:self.keychainStorage identity:self.eThree.identity completion:^(VSSSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        [syncKeyStorage storeEntryWithName:self.eThree.identity data:data meta:nil completion:^(VSSKeychainEntry *entry, NSError *error) {
            XCTAssert(error == nil);

            sleep(2);

            NSString *newPassword = [[NSUUID alloc] init].UUIDString;
            [self.eThree changePasswordFrom:self.password to:newPassword completion:^(NSError *error) {
                XCTAssert(error == nil);

                sleep(2);

                [self.eThree restorePrivateKeyWithPassword:self.password completion:^(NSError *error) {
                    XCTAssert(error.code == VTEEThreeErrorWrongPassword);

                    sleep(2);

                    [self.eThree restorePrivateKeyWithPassword:newPassword completion:^(NSError *error) {
                        XCTAssert(error == nil);

                        NSError *err;
                        VSSKeychainEntry *retrievedEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity
                                                                                          queryOptions:nil
                                                                                                 error:&err];
                        XCTAssert(retrievedEntry != nil && err == nil);
                        XCTAssert([retrievedEntry.data isEqualToData:data]);

                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];


    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test04_STE_18 {
    XCTestExpectation *ex = [self expectationWithDescription:@"ResetPrivateKeyBackup tests"];

    [self.eThree resetPrivateKeyBackupWithPassword:self.password completion:^(NSError *error) {
        XCTAssert(error != nil);

        NSError *err;
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
        NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey error:&err];

        sleep(2);

        __weak typeof(self) weakSelf = self;
        [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password keychainStorage:self.keychainStorage identity:self.eThree.identity completion:^(VSSSyncKeyStorage *syncKeyStorage, NSError *error) {
            XCTAssert(error == nil);

            [syncKeyStorage storeEntryWithName:self.eThree.identity data:data meta:nil completion:^(VSSKeychainEntry *entry, NSError *error) {
                XCTAssert(error == nil);

                sleep(2);

                [self.eThree resetPrivateKeyBackupWithPassword:self.password completion:^(NSError *error) {
                    XCTAssert(error == nil);

                    [syncKeyStorage syncWithCompletion:^(NSError *error) {
                        XCTAssert(error == nil);

                        NSError *err;
                        VSSKeychainEntry *entry = [syncKeyStorage retrieveEntryWithName:self.eThree.identity error:&err];
                        XCTAssert(err != nil && entry == nil);

                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test05_STE_19 {
    XCTestExpectation *ex = [self expectationWithDescription:@"ResetPrivateKeyBackup without pasword test"];

    [self.eThree resetPrivateKeyBackupWithPassword:self.password completion:^(NSError *error) {
        XCTAssert(error != nil);

        NSError *err;
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
        NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey error:&err];

        sleep(2);

        __weak typeof(self) weakSelf = self;
        [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password keychainStorage:self.keychainStorage identity:self.eThree.identity completion:^(VSSSyncKeyStorage *syncKeyStorage, NSError *error) {
            XCTAssert(error == nil);

            [syncKeyStorage storeEntryWithName:self.eThree.identity data:data meta:nil completion:^(VSSKeychainEntry *entry, NSError *error) {
                XCTAssert(error == nil);

                sleep(2);

                [self.eThree resetPrivateKeyBackupWithPassword:nil completion:^(NSError *error) {
                    XCTAssert(error == nil);

                    [syncKeyStorage syncWithCompletion:^(NSError *error) {
                        XCTAssert(error == nil);

                        NSError *err;
                        VSSKeychainEntry *entry = [syncKeyStorage retrieveEntryWithName:self.eThree.identity error:&err];
                        XCTAssert(err != nil && entry == nil);

                        [ex fulfill];
                    }];
                }];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
        XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
