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

#import "VTETestCaseBase.h"

@interface VTE001_EncryptionTests : VTETestCaseBase

@end

@implementation VTE001_EncryptionTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)test_STE_1 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Look up keys should return published public keys"];

    NSMutableArray *identities = [NSMutableArray array];
    NSMutableArray *publicKeys = [NSMutableArray array];

    NSError *error;
    for (int i = 0; i < 3; i++) {
        VSSCard *card = [self.utils publishCardWithIdentity:nil error:&error];
        XCTAssert(card != nil && error == nil);
        [identities addObject:card.identity];
        [publicKeys addObject:card.publicKey];
    }

    [self.eThree lookupPublicKeysOf:identities completion:^(NSDictionary<NSString *, VSMVirgilPublicKey *> *foundPublicKeys, NSError *error) {
        XCTAssert(error == nil);
        XCTAssert([self.utils isPublicKeysEqualWithKeys1:foundPublicKeys.allValues keys2:publicKeys]);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test_STE_2 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Look up keys by empty array of identities should throw error"];

    [self.eThree lookupPublicKeysOf:@[] completion:^(NSDictionary<NSString *, VSMVirgilPublicKey *> *foundPublicKeys, NSError *error) {
        XCTAssert(error.code == VTEEThreeErrorMissingIdentities);

        [ex fulfill];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
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

                [eThree1 lookupPublicKeysOf:@[eThree2.identity] completion:^(NSDictionary<NSString *, VSMVirgilPublicKey *> *foundPublicKeys, NSError *error) {
                    XCTAssert(error == nil);
                    XCTAssert(foundPublicKeys.count > 0);

                    NSString *plainText = [[NSUUID alloc] init].UUIDString;
                    NSError *err;
                    NSString *encrypted = [eThree1 encryptWithText:plainText for:foundPublicKeys error:&err];
                    XCTAssert(err == nil);

                    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
                    XCTAssert(err == nil);

                    NSString *decrypted = [eThree2 decryptWithText:encrypted from:keyPair.publicKey error:&err];
                    XCTAssert(err != nil && decrypted == nil);

                    [eThree2 lookupPublicKeysOf:@[eThree1.identity] completion:^(NSDictionary<NSString *, VSMVirgilPublicKey *> *foundPublicKeys, NSError *error) {
                        XCTAssert(error == nil);
                        XCTAssert(foundPublicKeys.count > 0);

                        NSError *err;
                        NSString *decrypted = [eThree2 decryptWithText:encrypted from:foundPublicKeys[eThree1.identity] error:&err];
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

        NSError *err;
        NSString *plainText = [[NSUUID alloc] init].UUIDString;
        NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&err];
        XCTAssert(err == nil);

        [self.eThree lookupPublicKeysOf:@[self.eThree.identity] completion:^(NSDictionary<NSString *, VSMVirgilPublicKey *> *foundPublicKeys, NSError *error) {
            XCTAssert(error == nil);
            XCTAssert(foundPublicKeys.count > 0);

            NSError *err;
            NSData *encryptedData = [self.crypto encrypt:plainData for:foundPublicKeys.allValues error:&err];
            XCTAssert(err == nil);

            NSString *encryptedString = [encryptedData base64EncodedStringWithOptions:0];
            XCTAssert(encryptedString != nil);

            NSString *decrypted = [self.eThree decryptWithText:encryptedString from:keyPair.publicKey error:&err];
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

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);

    NSString *encrypted = [self.eThree encryptWithText:@"plainText" for:@{self.eThree.identity: keyPair.publicKey} error:&error];
    XCTAssert(error.code == VTEEThreeErrorMissingPrivateKey);
    XCTAssert(encrypted == nil);

    error = nil;

    NSString *decrypted = [self.eThree decryptWithText:@"" from:keyPair.publicKey error:&error];
    XCTAssert(error.code == VTEEThreeErrorMissingPrivateKey);
    XCTAssert(decrypted == nil);
}

- (void)test_STE_7 {
    NSError *error;

    VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:&error];
    XCTAssert(error == nil);

    VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
    NSData *exportedKey = [exporter exportPrivateKeyWithPrivateKey:keyPair.privateKey error:&error];
    XCTAssert(error == nil);

    NSDictionary *meta = @{ @"isPublished": @"true"};

    VSSKeychainEntry *entry = [self.keychainStorage storeWithData:exportedKey withName:self.eThree.identity meta:meta error:&error];
    XCTAssert(error == nil && entry != nil);

    NSString *plainText = [[NSUUID alloc] init].UUIDString;
    NSString *encrypted = [self.eThree encryptWithText:plainText for:nil error:&error];
    XCTAssert(error == nil);

    NSString *decrypted = [self.eThree decryptWithText:encrypted from:nil error:&error];
    XCTAssert(error == nil);
    XCTAssert([decrypted isEqualToString:plainText]);
}

@end
