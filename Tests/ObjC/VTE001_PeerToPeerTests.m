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

#import "VTETestBase.h"

@interface VTE001_PeerToPeerTests : VTETestBase

@end

@implementation VTE001_PeerToPeerTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)test001_STE_3 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Simple encrypt decrypt should success"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        VTEEThree *eThree1 = self.eThree;

        VTEEThree *eThree2 = [self.utils setupEThreeWithStorageParams:self.keychainStorage.storageParams];
        XCTAssert(eThree2 != nil);

        [eThree2 registerWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);

            [eThree1 findUserWith:eThree2.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                XCTAssert(card != nil && error == nil);

                NSString *plainText = [[NSUUID alloc] init].UUIDString;
                NSError *err;
                NSString *encrypted = [eThree1 authEncryptText:plainText forUser:card error:&err];
                XCTAssert(err == nil);

                VSSCard *otherCard = [self.utils publishCardWithIdentity:nil previousCardId:nil];
                XCTAssert(err == nil);

                NSString *decrypted = [eThree2 authDecryptText:encrypted fromUser:otherCard error:&err];
                XCTAssert(err != nil && decrypted == nil);

                [eThree2 findUserWith:eThree1.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                    XCTAssert(card != nil && error == nil);

                    NSError *err;
                    NSString *decrypted = [eThree2 authDecryptText:encrypted fromUser:card error:&err];
                    XCTAssert(err == nil);
                    XCTAssert([decrypted isEqualToString:plainText]);

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

- (void)test002_STE_4 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Encrypt for empty array of keys should throw error"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        NSString *encrypted = [self.eThree authEncryptText:@"plaintext" forUsers:@{} error:&err];
        XCTAssert(err.code == VTEEThreeErrorMissingPublicKey && encrypted == nil);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test003_STE_5 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Should throw error if decrypted text is not verified"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        NSString *plainText = [[NSUUID alloc] init].UUIDString;
        NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];

        [self.eThree findUserWith:self.eThree.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
            XCTAssert(card != nil && error == nil);

            NSError *err;
            NSData *encryptedData = [self.crypto encrypt:plainData for:@[card.publicKey] enablePadding:NO error:&err];
            XCTAssert(err == nil);

            NSString *encryptedString = [encryptedData base64EncodedStringWithOptions:0];
            XCTAssert(encryptedString != nil);

            VSSCard *otherCard = [self.utils publishCardWithIdentity:nil previousCardId:nil];
            XCTAssert(err == nil);

            NSString *decrypted = [self.eThree authDecryptText:encryptedString fromUser:otherCard error:&err];
            XCTAssert(err != nil && decrypted == nil);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test004_STE_6 {
    NSError *error;
    [self.keychainStorage deleteEntryWithName:self.eThree.identity queryOptions:nil error:nil];

    VSSCard *card = [self.utils publishCardWithIdentity:nil previousCardId:nil];
    XCTAssert(error == nil);

    NSString *encrypted = [self.eThree authEncryptText:@"plainText" forUsers:@{self.eThree.identity: card} error:&error];
    XCTAssert(error.code == VTEEThreeErrorMissingPrivateKey);
    XCTAssert(encrypted == nil);

    error = nil;

    NSString *decrypted = [self.eThree authDecryptText:@"" fromUser:card error:&error];
    XCTAssert(error.code == VTEEThreeErrorMissingPrivateKey);
    XCTAssert(decrypted == nil);
}

- (void)test005_STE_22 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Should encrypt then decrypt streams"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        NSUUID *identifier = [[NSUUID alloc] init];
        uuid_t uuid;
        [identifier getUUIDBytes:uuid];
        NSUInteger size = 100;
        NSData *data = [NSData dataWithBytes:uuid length:size];
        XCTAssert(data != nil);

        NSInputStream *inputStream1 = [[NSInputStream alloc] initWithData:data];
        NSOutputStream *outputStream1 = [[NSOutputStream alloc] initToMemory];

        [self.eThree authEncryptStream:inputStream1 withSize:size toStream:outputStream1 forUsers:nil error:&err];

        XCTAssert(err == nil);

        NSData *encryptedData = [outputStream1 propertyForKey:NSStreamDataWrittenToMemoryStreamKey];

        NSInputStream *inputStream2 = [[NSInputStream alloc] initWithData:encryptedData];
        NSOutputStream *outputStream2 = [[NSOutputStream alloc] initToMemory];

        [self.eThree authDecrypt:inputStream2 to:outputStream2 from:nil error:&err];
        XCTAssert(err == nil);

        NSData *decryptedData = [outputStream2 propertyForKey:NSStreamDataWrittenToMemoryStreamKey];

        XCTAssert([data isEqualToData:decryptedData]);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test006_STE_40 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Decrypt text, which was encrypted with old card"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        VTEEThree *eThree1 = self.eThree;

        VTEEThree *eThree2 = [self.utils setupEThreeWithStorageParams:self.keychainStorage.storageParams];
        XCTAssert(eThree2 != nil);

        [eThree2 registerWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);

            [eThree1 findUserWith:eThree2.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                XCTAssert(card != nil && error == nil);

                NSDate *date1 = [[NSDate alloc] init];
                NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
                [formatter setDateFormat:@"HH:mm:ss.SS"];
                NSLog(@"AAA %@",[formatter stringFromDate:date1]);

                sleep(1);

                NSString *plainText1 = [[NSUUID alloc] init].UUIDString;
                NSError *err;
                NSString *encrypted1 = [eThree1 authEncryptText:plainText1 forUsers:@{card.identity: card} error:&err];
                XCTAssert(err == nil);

                [eThree1 cleanUpAndReturnError:&err];

                [eThree1 rotatePrivateKeyWithCompletion:^(NSError *error) {
                    XCTAssert(error == nil);

                    NSDate *date2 = [[NSDate alloc] init];
                    NSLog(@"AAA %@",[formatter stringFromDate:date1]);

                    NSString *plainText2 = [[NSUUID alloc] init].UUIDString;
                    NSError *err;
                    NSString *encrypted2 = [eThree1 authEncryptText:plainText2 forUsers:@{card.identity: card} error:&err];
                    XCTAssert(err == nil);

                    [eThree2 findUserWith:eThree1.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                        XCTAssert(card != nil && error == nil);

                        NSError *err;
                        NSString *tmp1 = [eThree2 authDecryptText:encrypted1 fromUser:card error:&err];
                        XCTAssert(err != nil && tmp1 == nil);

                        err = nil;

                        NSString *tmp2 = [eThree2 authDecryptText:encrypted1 fromUser:card date:date2 error:&err];
                        XCTAssert(err != nil && tmp2 == nil);

                        err = nil;

                        NSLog(@"AAA %@",[formatter stringFromDate:card.createdAt]);
                        NSString *decrypted1 = [eThree2 authDecryptText:encrypted1 fromUser:card date:date1 error:&err];
                        XCTAssert(err == nil);

                        NSString *tmp3 = [eThree2 authDecryptText:encrypted2 fromUser:card date:date1 error:&err];
                        XCTAssert(err != nil && tmp3 == nil);

                        err = nil;

                        NSString *decrypted2 = [eThree2 authDecryptText:encrypted2 fromUser:card date:date2 error:&err];
                        XCTAssert(err == nil);


                        XCTAssert([decrypted1 isEqualToString:plainText1]);
                        XCTAssert([decrypted2 isEqualToString:plainText2]);

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

- (void)test007_STE_41 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Simple encrypt decrypt with deprecated methods"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        VTEEThree *eThree1 = self.eThree;


        NSError *err;
        VTEEThree *eThree2 = [self.utils deprecatedSetupEThreeWithStorageParams:self.keychainStorage.storageParams error:&err];
        XCTAssert(eThree2 != nil && err == nil);

        [eThree2 registerWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);

            [eThree1 lookupPublicKeysOf:@[eThree2.identity] completion:^(NSDictionary<NSString *, VSMVirgilPublicKey *> *lookup, NSError *error) {
                XCTAssert(error == nil);
                XCTAssert(lookup.count > 0);

                NSString *plainText = [[NSUUID alloc] init].UUIDString;
                NSError *err;
                NSString *encrypted = [eThree1 encryptWithText:plainText for:lookup error:&err];
                XCTAssert(err == nil);

                [eThree2 lookupPublicKeysOf:@[eThree1.identity] completion:^(NSDictionary<NSString *, VSMVirgilPublicKey *> *lookup, NSError *error) {
                    XCTAssert(error == nil);
                    XCTAssert(lookup.count > 0);

                    NSError *err;
                    NSString *decrypted = [eThree2 decryptWithText:encrypted from:lookup[eThree1.identity] error:&err];
                    XCTAssert(err == nil);
                    XCTAssert([decrypted isEqualToString:plainText]);

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

- (void)test008_STE_71 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Simple encrypt decrypt with deprecated methods should succeed"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        VTEEThree *eThree1 = self.eThree;

        VTEEThree *eThree2 = [self.utils setupEThreeWithStorageParams:self.keychainStorage.storageParams];
        XCTAssert(eThree2 != nil);

        [eThree2 registerWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);

            [eThree1 findUserWith:eThree2.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                XCTAssert(card != nil && error == nil);

                NSString *plainText = [[NSUUID alloc] init].UUIDString;
                NSError *err;
                NSString *encrypted = [eThree1 encryptText:plainText forUser:card error:&err];
                XCTAssert(err == nil);

                VSSCard *otherCard = [self.utils publishCardWithIdentity:nil previousCardId:nil];
                XCTAssert(err == nil);

                NSString *decrypted = [eThree2 decryptText:encrypted fromUser:otherCard error:&err];
                XCTAssert(err != nil && decrypted == nil);

                [eThree2 findUserWith:eThree1.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                    XCTAssert(card != nil && error == nil);

                    NSError *err;
                    NSString *decrypted = [eThree2 decryptText:encrypted fromUser:card error:&err];
                    XCTAssert(err == nil);
                    XCTAssert([decrypted isEqualToString:plainText]);

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

- (void)test009_STE_88 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Decrypt stream, encrypted and signed as data should succeed"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        VTEEThree *eThree1 = self.eThree;

        VTEEThree *eThree2 = [self.utils setupEThreeWithStorageParams:self.keychainStorage.storageParams];
        XCTAssert(eThree2 != nil);

        [eThree2 registerWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);
            
            [eThree1 findUserWith:eThree1.identity forceReload:false completion:^(VSSCard *card1, NSError *error) {
                XCTAssert(card1 != nil && error == nil);

                [eThree1 findUserWith:eThree2.identity forceReload:false completion:^(VSSCard *card2, NSError *error) {
                    XCTAssert(card2 != nil && error == nil);
            
                    NSError *err;
                    NSData *data = [self.utils.crypto generateRandomDataOfSize:10 error:&err];
                    XCTAssert(data != nil && err == nil);

                    NSData *encrypted = [eThree1 authEncryptData:data forUser:card2 error:&err];
                    XCTAssert(encrypted != nil && err == nil);
                    
                    NSInputStream *inputStream = [[NSInputStream alloc] initWithData:encrypted];
                    NSOutputStream *outputStream = [[NSOutputStream alloc] initToMemory];

                    [eThree2 authDecrypt:inputStream to:outputStream from:card1 error:&err];
                    XCTAssert(err == nil);
        
                    NSData *decryptedData = [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];

                    XCTAssert([data isEqualToData:decryptedData]);

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

- (void)test010_STE_89__streams_compatibility {
    NSString *privateKeyString = self.utils.streamsCompatibilityDict[@"private_key"];
    NSString *encryptedString = self.utils.streamsCompatibilityDict[@"encrypted_data"];
    NSString *originString = self.utils.streamsCompatibilityDict[@"origin_data"];
    NSData *privateKeyData = [[NSData alloc] initWithBase64EncodedString:privateKeyString options:0];
    NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:encryptedString options:0];
    NSData *originData = [[NSData alloc] initWithBase64EncodedString:originString options:0];

    NSError *error;
    VSMVirgilKeyPair *keyPair = [self.utils.crypto importPrivateKeyFrom:privateKeyData error:&error];
    XCTAssert(error == nil);

    VTEEThree* ethree = [self.utils setupDeviceWithIdentity:nil
                                                    keyPair:keyPair
                                                keyPairType:VSMKeyPairTypeEd25519
                                                   register:false error:&error];
    XCTAssert(error == nil);

    NSInputStream *inputStream = [[NSInputStream alloc] initWithData:encryptedData];
    NSOutputStream *outputStream = [[NSOutputStream alloc] initToMemory];

    [ethree authDecrypt:inputStream to:outputStream from:nil error:&error];
    XCTAssert(error == nil);

    NSData *decryptedData = [outputStream propertyForKey:NSStreamDataWrittenToMemoryStreamKey];

    XCTAssert([originData isEqualToData:decryptedData]);
}

@end
