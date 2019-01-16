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
@import VirgilE3Kit;

#import "VTETestsConst.h"
#import "VTETestUtils.h"

static const NSTimeInterval timeout = 20.;

@interface VTE002_AuthenticationTests : XCTestCase

@property (nonatomic) VTETestsConst *consts;
@property (nonatomic) VSMVirgilCrypto *crypto;
@property (nonatomic) VTETestUtils *utils;
@property (nonatomic) VSSKeychainStorage *keychainStorage;
@property (nonatomic) VTEEThree *eThree;
@property (nonatomic) NSString *password;


@end

@implementation VTE002_AuthenticationTests

- (void)setUp {
    [super setUp];

    self.password = [[NSUUID alloc] init].UUIDString;
    self.consts = [[VTETestsConst alloc] init];
    self.crypto = [[VSMVirgilCrypto alloc] initWithDefaultKeyType:VSCKeyTypeFAST_EC_ED25519 useSHA256Fingerprints:false];
    self.utils = [[VTETestUtils alloc] initWithCrypto:self.crypto consts:self.consts];

    VSSKeychainStorageParams *params;
#if TARGET_OS_IOS || TARGET_OS_TV
    params = [VSSKeychainStorageParams makeKeychainStorageParamsWithAccessGroup:nil accessibility:nil error:nil];
#elif TARGET_OS_OSX
    params = [VSSKeychainStorageParams makeKeychainStorageParamsWithTrustedApplications:@[] error:nil];
#endif
    self.keychainStorage = [[VSSKeychainStorage alloc] initWithStorageParams:params];
    [self.keychainStorage deleteAllEntriesAndReturnError:nil];

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    NSString *identity = [[NSUUID alloc] init].UUIDString;
    [VTEEThree initializeWithTokenCallback:^(void (^completionHandler)(NSString *, NSError *)) {
        NSError *error;
        NSString *token = [self.utils getTokenStringWithIdentity:identity error:&error];

        completionHandler(token, error);
    } storageParams:nil completion:^(VTEEThree *eThree, NSError *error) {
        XCTAssert(eThree != nil && error == nil);
        self.eThree = eThree;

        dispatch_semaphore_signal(sema);
    }];

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
}

- (void)tearDown {
    [super tearDown];
}

-(void)test_STE_8 {
    NSError *error;

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey];
    VSSKeychainEntry *entry = [self.keychainStorage storeWithData:data withName:self.eThree.identity meta:nil error:&error];
    XCTAssert(entry != nil && error == nil);

    [self.eThree cleanUpAndReturnError:&error];
    XCTAssert(error == nil);

    VSSKeychainEntry *retrievedEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&error];
    XCTAssert(retrievedEntry == nil && error != nil);
}

- (void)test_STE_9 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Register should create local key and publish card"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        VSSKeychainEntry *keyEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
        XCTAssert(err == nil && keyEntry != nil);

        [self.eThree.cardManager searchCardsWithIdentity:self.eThree.identity completion:^(NSArray<VSSCard *> *cards, NSError *error) {
            XCTAssert(error == nil && cards.firstObject != nil);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test_STE_10 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Register should throw error if card already exists"];

    VSSCard *card = [self.utils publishCardWithIdentity:self.eThree.identity];
    XCTAssert(card != nil);

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error != nil && error.code == VTEEThreeErrorUserIsAlreadyRegistered);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test_STE_11 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Register should throw error if local key already exists"];

    NSError *error;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey];
    VSSKeychainEntry *entry = [self.keychainStorage storeWithData:data withName:self.eThree.identity meta:nil error:&error];
    XCTAssert(entry != nil && error == nil);

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error != nil && error.code == VTEEThreeErrorPrivateKeyExists);

        [ex fulfill];
    }];


    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test_STE_12 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Rotating key should throw error if card doesn't exists"];

    [self.eThree rotatePrivateKeyWithCompletion:^(NSError *error) {
        XCTAssert(error != nil && error.code == VTEEThreeErrorUserIsNotRegistered);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test_STE_13 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Rotating key should throw error if local key exists"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        [self.eThree rotatePrivateKeyWithCompletion:^(NSError *error) {
            XCTAssert(error != nil && error.code == VTEEThreeErrorPrivateKeyExists);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test_STE_14 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Rotating key should throw error if local key exists"];

    VSSCard *card = [self.utils publishCardWithIdentity:self.eThree.identity];
    XCTAssert(card != nil);

    [self.eThree rotatePrivateKeyWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        [self.eThree.cardManager searchCardsWithIdentity:self.eThree.identity completion:^(NSArray<VSSCard *> *cards, NSError *error) {
            XCTAssert(error == nil && cards.firstObject != nil);

            XCTAssert([cards.firstObject.previousCardId isEqualToString:card.identifier]);
            XCTAssert(![cards.firstObject.identifier isEqualToString:card.identifier]);

            VSSKeychainEntry *retrievedEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&error];
            XCTAssert(retrievedEntry != nil && error == nil);

            NSError *err;
            VSMVirgilPrivateKey *privateKey = [self.crypto importPrivateKeyFrom:retrievedEntry.data password:nil error:&err];
            VSMVirgilPublicKey *publicKey = [self.crypto extractPublicKeyFrom:privateKey error:&err];
            XCTAssert(err == nil);

            NSData *key1 = [self.crypto exportPublicKey:(VSMVirgilPublicKey *)card.publicKey];
            NSData *key2 = [self.crypto exportPublicKey:publicKey];
            XCTAssert(![key1 isEqualToData:key2]);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
