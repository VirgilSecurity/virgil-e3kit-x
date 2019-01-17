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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
@import VirgilSDK;
@import VirgilE3Kit;
@import VirgilCrypto;
@import VirgilCryptoApiImpl;
@import VirgilSDKKeyknox;

#import "VTETestsConst.h"

#if TARGET_OS_IOS
    #import "VirgilE3Kit_iOS_Tests-Swift.h"
#elif TARGET_OS_TV
    #import "VirgilE3Kit_tvOS_Tests-Swift.h"
#elif TARGET_OS_OSX
    #import "VirgilE3Kit_macOS_Tests-Swift.h"
#endif

static const NSTimeInterval timeout = 20.;

@interface VTE003_KeyBackupTests : XCTestCase

@property (nonatomic) VTETestsConst *consts;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VTETestUtils *utils;
@property (nonatomic) VSSKeychainStorage *keychainStorage;
@property (nonatomic) VTEEThree *eThree;
@property (nonatomic) NSString *password;


@end

@implementation VTE003_KeyBackupTests

- (void)setUp {
    [super setUp];

    self.password = [[NSUUID alloc] init].UUIDString;
    self.consts = [[VTETestsConst alloc] init];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:false];
    self.utils = [[VTETestUtils alloc] initWithCrypto:self.crypto consts:self.consts];

    VSSKeychainStorageParams *params;
#if TARGET_OS_IOS || TARGET_OS_TV
    params = [VSSKeychainStorageParams makeKeychainStorageParamsWithAppName:@"test" accessGroup:nil accessibility:nil error:nil];
#elif TARGET_OS_OSX
    params = [VSSKeychainStorageParams makeKeychainStorageParamsWithAppName:@"test" trustedApplications:@[] error:nil];
#endif
    self.keychainStorage = [[VSSKeychainStorage alloc] initWithStorageParams:params];
    [self.keychainStorage deleteAllEntriesAndReturnError:nil];

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    NSString *identity = [[NSUUID alloc] init].UUIDString;
    [VTEEThree initializeWithTokenCallback:^(void (^completionHandler)(NSString *, NSError *)) {
        NSString *token = [self.utils getTokenStringWithIdentity:identity];

        completionHandler(token, nil);
    } storageParams:params completion:^(VTEEThree *eThree, NSError *error) {
        XCTAssert(eThree != nil && error == nil);
        self.eThree = eThree;

        dispatch_semaphore_signal(sema);
    }];

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
}

- (void)tearDown {
    [super tearDown];
}

- (void)test_STE_15 {
    XCTestExpectation *ex = [self expectationWithDescription:@"BackupPrivateKey tests"];

    [self.eThree backupPrivateKeyWithPassword:self.password completion:^(NSError *error) {
        XCTAssert(error.code == VTEEThreeErrorMissingPrivateKey);

        sleep(2);

        NSError *err;
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
        NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey];
        VSSKeychainEntry *entry = [self.keychainStorage storeWithData:data withName:self.eThree.identity meta:nil error:&err];
        XCTAssert(entry != nil && err == nil);

        [self.eThree backupPrivateKeyWithPassword:self.password completion:^(NSError *error) {
            XCTAssert(error == nil);

            sleep(2);

            __weak typeof(self) weakSelf = self;
            [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password keychainStorage:self.keychainStorage identity:self.eThree.identity completion:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
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

- (void)test_STE_16 {
    XCTestExpectation *ex = [self expectationWithDescription:@"RestorePrivateKey tests"];

    NSError *err;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
    NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey];

    __weak typeof(self) weakSelf = self;
    [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password keychainStorage:self.keychainStorage identity:self.eThree.identity completion:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        [syncKeyStorage storeEntryWithName:self.eThree.identity data:data meta:nil completion:^(VSSKeychainEntry *entry, NSError *error) {
            XCTAssert(error == nil);

            sleep(2);

            [self.eThree restorePrivateKeyWithPassword:self.password completion:^(NSError *error) {
                XCTAssert(error == nil);

                NSError *err;
                VSSKeychainEntry *retrievedEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
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

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test_STE_17 {
    XCTestExpectation *ex = [self expectationWithDescription:@"ChangePrivateKeyPassword tests"];

    NSError *err;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
    NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey];

    __weak typeof(self) weakSelf = self;
    [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password keychainStorage:self.keychainStorage identity:self.eThree.identity completion:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        [syncKeyStorage storeEntryWithName:self.eThree.identity data:data meta:nil completion:^(VSSKeychainEntry *entry, NSError *error) {
            XCTAssert(error == nil);

            sleep(2);

            NSString *newPassword = [[NSUUID alloc] init].UUIDString;
            [self.eThree changePasswordFrom:self.password to:newPassword completion:^(NSError *error) {
                XCTAssert(error == nil);

                sleep(2);

                [self.eThree restorePrivateKeyWithPassword:self.password completion:^(NSError *error) {
                    XCTAssert(error != nil);

                    sleep(2);

                    [self.eThree restorePrivateKeyWithPassword:newPassword completion:^(NSError *error) {
                        XCTAssert(error == nil);

                        NSError *err;
                        VSSKeychainEntry *retrievedEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
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

- (void)test_STE_18 {
    XCTestExpectation *ex = [self expectationWithDescription:@"ResetPrivateKeyBackup tests"];

    [self.eThree resetPrivateKeyBackupWithPassword:self.password completion:^(NSError *error) {
        XCTAssert(error != nil);

        NSError *err;
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
        NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey];

        sleep(2);

        __weak typeof(self) weakSelf = self;
        [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password keychainStorage:self.keychainStorage identity:self.eThree.identity completion:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
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

@end
