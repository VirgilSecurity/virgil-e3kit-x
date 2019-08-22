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

@interface VTE002_AuthenticationTests : VTETestBase

@end

@implementation VTE002_AuthenticationTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

-(void)test01_STE_8 {
    NSError *error;

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey error:&error];
    XCTAssert(error == nil);
    VSSKeychainEntry *entry = [self.keychainStorage storeWithData:data
                                                         withName:self.eThree.identity
                                                             meta:nil
                                                     queryOptions:nil
                                                            error:&error];
    XCTAssert(entry != nil && error == nil);

    [self.eThree cleanUpAndReturnError:&error];
    XCTAssert(error == nil);

    VSSKeychainEntry *retrievedEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity
                                                                      queryOptions:nil
                                                                             error:&error];
    XCTAssert(retrievedEntry == nil && error != nil);
}

- (void)test02_STE_9 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Register should create local key and publish card"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        VSSKeychainEntry *keyEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity
                                                                    queryOptions:nil
                                                                           error:&err];
        XCTAssert(err == nil && keyEntry != nil);

        [self.eThree.cardManager searchCardsWithIdentities:@[self.eThree.identity] completion:^(NSArray<VSSCard *> *cards, NSError *error) {
            XCTAssert(error == nil && cards.firstObject != nil);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test03_STE_10 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Register should throw error if card already exists"];

    NSError *error;
    VSSCard *card = [self.utils publishCardWithIdentity:self.eThree.identity previousCardId:nil];
    XCTAssert(card != nil && error == nil);

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error != nil && error.code == VTEEThreeErrorUserIsAlreadyRegistered);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test04_STE_11 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Register should throw error if local key already exists"];

    NSString *identity = [[NSUUID alloc] init].UUIDString;

    VSSCard *card __unused = [self.utils publishCardWithIdentity:identity previousCardId:nil];

    NSError *error;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    NSData *data = [self.crypto exportPrivateKey:keyPair.privateKey error:&error];
    VSSKeychainEntry *entry = [self.keychainStorage storeWithData:data
                                                         withName:identity
                                                             meta:nil
                                                     queryOptions:nil
                                                            error:&error];
    XCTAssert(entry != nil && error == nil);

    VTEEThree *eThree = [[VTEEThree alloc] initWithIdentity:identity tokenCallback:^(void (^completionHandler)(NSString *, NSError *)) {
        NSString *token = [self.utils getTokenStringWithIdentity:identity];

        completionHandler(token, nil);
    } changedKeyDelegate:nil storageParams:self.keychainStorage.storageParams error:&error];

    XCTAssert(eThree != nil && error == nil);

    [eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error != nil && error.code == VTEEThreeErrorPrivateKeyExists);

        [ex fulfill];
    }];


    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test05_STE_12 {
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

-(void)test06_STE_13 {
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

-(void)test07_STE_14 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Rotating key should throw error if local key exists"];

    NSError *error;
    VSSCard *card = [self.utils publishCardWithIdentity:self.eThree.identity previousCardId:nil];
    XCTAssert(card != nil && error == nil);

    [self.eThree rotatePrivateKeyWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        [self.eThree.cardManager searchCardsWithIdentities:@[self.eThree.identity] completion:^(NSArray<VSSCard *> *cards, NSError *error) {
            XCTAssert(error == nil && cards.firstObject != nil);

            XCTAssert([cards.firstObject.previousCardId isEqualToString:card.identifier]);
            XCTAssert(![cards.firstObject.identifier isEqualToString:card.identifier]);

            NSError *err;
            VSSKeychainEntry *retrievedEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity
                                                                              queryOptions:nil
                                                                                     error:&err];
            XCTAssert(retrievedEntry != nil && err == nil);

            VSMVirgilKeyPair *keyPair = [self.crypto importPrivateKeyFrom:retrievedEntry.data error:&err];
            XCTAssert(err == nil);

            NSData *key1 = [self.crypto exportPublicKey:(VSMVirgilPublicKey *)card.publicKey error:&err];
            NSData *key2 = [self.crypto exportPublicKey:keyPair.publicKey error:&err];
            XCTAssert(err == nil);
            XCTAssert(![key1 isEqualToData:key2]);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

-(void)test08_STE_20 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Unregister should revoke Virgil Card"];

    [self.eThree unregisterWithCompletion:^(NSError *error) {
        XCTAssert(error != nil);

        [self.eThree registerWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);

            [self.eThree unregisterWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);

                VSSKeychainEntry *retrievedEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity
                                                                                  queryOptions:nil
                                                                                         error:&error];
                XCTAssert(retrievedEntry == nil && error != nil);

                [self.eThree.cardManager searchCardsWithIdentities:@[self.eThree.identity] completion:^(NSArray<VSSCard *> *cards, NSError *error) {
                    XCTAssert(error == nil && cards.firstObject == nil);

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

-(void)test09_STE_44 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Register with provided key should publish Card and save locally"];

    NSError *error;
    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairOfType:VSMKeyPairTypeSecp256r1 error:&error];
    XCTAssert(error == nil);

    NSData *exportedPrivateKey = [self.crypto exportPrivateKey:keyPair.privateKey error:&error];

    [self.eThree registerWith:keyPair completion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        VSSKeychainEntry *keyEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity
                                                                    queryOptions:nil
                                                                           error:&err];
        XCTAssert(err == nil && keyEntry != nil);
        XCTAssert([exportedPrivateKey isEqualToData:keyEntry.data]);

        [self.eThree.cardManager searchCardsWithIdentities:@[self.eThree.identity] completion:^(NSArray<VSSCard *> *cards, NSError *error) {
            XCTAssert(error == nil && [cards.firstObject.identity isEqualToString:self.eThree.identity]);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
