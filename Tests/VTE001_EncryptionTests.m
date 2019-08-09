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

@interface VTE001_EncryptionTests : VTETestBase

@end

@implementation VTE001_EncryptionTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)test_STE_3 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Simple encrypt decrypt should success"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        VTEEThree *eThree1 = self.eThree;

        NSString *identity = [[NSUUID alloc] init].UUIDString;
        [VTEEThree initializeWithTokenCallback:^(void (^completionHandler)(NSString *, NSError *)) {
            NSString *token = [self.utils getTokenStringWithIdentity:identity];

            completionHandler(token, nil);
        } storageParams:self.keychainStorage.storageParams completion:^(VTEEThree *eThree2, NSError *error) {
            XCTAssert(eThree2 != nil && error == nil);

            [eThree2 registerWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);

                [eThree1 lookupCardOf:eThree2.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                    XCTAssert(card != nil && error == nil);

                    NSString *plainText = [[NSUUID alloc] init].UUIDString;
                    NSError *err;
                    NSString *encrypted = [eThree1 encryptWithText:plainText for:@{card.identity: card} error:&err];
                    XCTAssert(err == nil);

                    VSSCard *otherCard = [self.utils publishCardWithIdentity:nil previousCardId:nil];
                    XCTAssert(err == nil);

                    NSString *decrypted = [eThree2 decryptWithText:encrypted from:otherCard date:nil error:&err];
                    XCTAssert(err != nil && decrypted == nil);

                    [eThree2 lookupCardOf:eThree1.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                        XCTAssert(card != nil && error == nil);

                        NSError *err;
                        NSString *decrypted = [eThree2 decryptWithText:encrypted from:card date:nil error:&err];
                        XCTAssert(err == nil);
                        XCTAssert([decrypted isEqualToString:plainText]);

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

- (void)test_STE_4 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Encrypt for empty array of keys should throw error"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        NSString *encrypted = [self.eThree encryptWithText:@"plaintext" for:@{} error:&err];
        XCTAssert(err.code == VTEEThreeErrorMissingPublicKey && encrypted == nil);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test_STE_5 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Should throw error if decrypted text is not verified"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        NSString *plainText = [[NSUUID alloc] init].UUIDString;
        NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];

        [self.eThree lookupCardOf:self.eThree.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
            XCTAssert(card != nil && error == nil);

            NSError *err;
            NSData *encryptedData = [self.crypto encrypt:plainData for:@[card.publicKey] error:&err];
            XCTAssert(err == nil);

            NSString *encryptedString = [encryptedData base64EncodedStringWithOptions:0];
            XCTAssert(encryptedString != nil);

            VSSCard *otherCard = [self.utils publishCardWithIdentity:nil previousCardId:nil];
            XCTAssert(err == nil);

            NSString *decrypted = [self.eThree decryptWithText:encryptedString from:otherCard date:nil error:&err];
            XCTAssert(err != nil && decrypted == nil);

            [ex fulfill];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test_STE_6 {
    NSError *error;
    [self.keychainStorage deleteEntryWithName:self.eThree.identity error: nil];

    VSSCard *card = [self.utils publishCardWithIdentity:nil previousCardId:nil];
    XCTAssert(error == nil);

    NSString *encrypted = [self.eThree encryptWithText:@"plainText" for:@{self.eThree.identity: card} error:&error];
    XCTAssert(error.code == VTEEThreeErrorMissingPrivateKey);
    XCTAssert(encrypted == nil);

    error = nil;

    NSString *decrypted = [self.eThree decryptWithText:@"" from:card date:nil error:&error];
    XCTAssert(error.code == VTEEThreeErrorMissingPrivateKey);
    XCTAssert(decrypted == nil);
}

- (void)test_STE_22 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Should encrypt then decrypt streams"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);

        NSError *err;
        NSUUID *identifier = [[NSUUID alloc] init];
        uuid_t uuid;
        [identifier getUUIDBytes:uuid];
        NSData *data = [NSData dataWithBytes:uuid length:100];
        XCTAssert(data != nil);

        NSInputStream *inputStream1 = [[NSInputStream alloc] initWithData:data];
        NSOutputStream *outputStream1 = [[NSOutputStream alloc] initToMemory];

        [self.eThree encrypt:inputStream1 to:outputStream1 for:nil error:&err];
        XCTAssert(err == nil);

        NSData *encryptedData = [outputStream1 propertyForKey:NSStreamDataWrittenToMemoryStreamKey];

        NSInputStream *inputStream2 = [[NSInputStream alloc] initWithData:encryptedData];
        NSOutputStream *outputStream2 = [[NSOutputStream alloc] initToMemory];

        [self.eThree decrypt:inputStream2 to:outputStream2 error:&err];
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

- (void)test_STE_37 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Decrypt text, which was encrypted with old card"];

    [self.eThree registerWithCompletion:^(NSError *error) {
        XCTAssert(error == nil);
        VTEEThree *eThree1 = self.eThree;

        NSString *identity = [[NSUUID alloc] init].UUIDString;
        [VTEEThree initializeWithTokenCallback:^(void (^completionHandler)(NSString *, NSError *)) {
            NSString *token = [self.utils getTokenStringWithIdentity:identity];

            completionHandler(token, nil);
        } storageParams:self.keychainStorage.storageParams completion:^(VTEEThree *eThree2, NSError *error) {
            XCTAssert(eThree2 != nil && error == nil);

            [eThree2 registerWithCompletion:^(NSError *error) {
                XCTAssert(error == nil);

                [eThree1 lookupCardOf:eThree2.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                    XCTAssert(card != nil && error == nil);

                    NSDate *date1 = [[NSDate alloc] init];
                    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
                    [formatter setDateFormat:@"HH:mm:ss.SS"];
                    NSLog(@"AAA %@",[formatter stringFromDate:date1]);

                    sleep(1);

                    NSString *plainText1 = [[NSUUID alloc] init].UUIDString;
                    NSError *err;
                    NSString *encrypted1 = [eThree1 encryptWithText:plainText1 for:@{card.identity: card} error:&err];
                    XCTAssert(err == nil);

                    [eThree1 cleanUpAndReturnError:&err];

                    [eThree1 rotatePrivateKeyWithCompletion:^(NSError *error) {
                        XCTAssert(error == nil);

                        NSDate *date2 = [[NSDate alloc] init];
                        NSLog(@"AAA %@",[formatter stringFromDate:date1]);

                        NSString *plainText2 = [[NSUUID alloc] init].UUIDString;
                        NSError *err;
                        NSString *encrypted2 = [eThree1 encryptWithText:plainText2 for:@{card.identity: card} error:&err];
                        XCTAssert(err == nil);

                        [eThree2 lookupCardOf:eThree1.identity forceReload:false completion:^(VSSCard *card, NSError *error) {
                            XCTAssert(card != nil && error == nil);

                            NSError *err;
                            NSString *tmp1 = [eThree2 decryptWithText:encrypted1 from:card date:nil error:&err];
                            XCTAssert(err != nil && tmp1 == nil);

                            err = nil;

                            NSString *tmp2 = [eThree2 decryptWithText:encrypted1 from:card date:date2 error:&err];
                            XCTAssert(err != nil && tmp2 == nil);

                            err = nil;

                            NSLog(@"AAA %@",[formatter stringFromDate:card.createdAt]);
                            NSString *decrypted1 = [eThree2 decryptWithText:encrypted1 from:card date:date1 error:&err];
                            XCTAssert(err == nil);

                            NSString *tmp3 = [eThree2 decryptWithText:encrypted2 from:card date:date1 error:&err];
                            XCTAssert(err != nil && tmp3 == nil);

                            err = nil;

                            NSString *decrypted2 = [eThree2 decryptWithText:encrypted2 from:card date:date2 error:&err];
                            XCTAssert(err == nil);


                            XCTAssert([decrypted1 isEqualToString:plainText1]);
                            XCTAssert([decrypted2 isEqualToString:plainText2]);

                            [ex fulfill];
                        }];
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
