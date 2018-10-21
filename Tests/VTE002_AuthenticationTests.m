//
//  VTE002_AuthenticationTests.m
//  VirgilE3Kit
//
//  Created by Eugen Pivovarov on 10/19/18.
//

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
@import VirgilSDK;
@import VirgilE3Kit;
@import VirgilCrypto;
@import VirgilSDK;
@import VirgilCryptoApiImpl;

#import "VTETestsConst.h"
#import "VTETestUtils.h"

static const NSTimeInterval timeout = 200.;

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

    VSSKeychainStorageParams *params = [VSSKeychainStorageParams makeKeychainStorageParamsWithTrustedApplications:@[] error:nil];
    self.keychainStorage = [[VSSKeychainStorage alloc] initWithStorageParams:params];

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    NSString *identity = [[NSUUID alloc] init].UUIDString;
    [VTEEThree initializeWithTokenCallback:^(void (^completionHandler)(NSString *, NSError *)) {
        NSError *error;
        NSString *token = [self.utils getTokenStringWithIdentity:identity error:&error];

        completionHandler(token, error);
    } completion:^(VTEEThree *eThree, NSError *error) {
        XCTAssert(eThree != nil && error == nil);
        self.eThree = eThree;

        dispatch_semaphore_signal(sema);
    }];

    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
}

- (void)tearDown {
    [super tearDown];
}

- (void)test01 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Bootstrap should create local key and publish card"];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
            XCTAssert(error == nil);

            NSError *err;
            VSSKeychainEntry *keyEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
            XCTAssert(err == nil && keyEntry != nil);

            NSDictionary *dict = keyEntry.meta;
            NSString *isPublished = dict[@"isPublished"];

            XCTAssert(isPublished.boolValue == true);

            [self.eThree.cardManager searchCardsWithIdentity:self.eThree.identity completion:^(NSArray<VSSCard *> *cards, NSError *error) {
                XCTAssert(error == nil && cards.firstObject != nil);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test02 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Bootstrap should create local, keyknox key and publish card"];

    NSError *err;
    [self.keychainStorage deleteAllEntriesAndReturnError:&err];
    XCTAssert(err == nil);

    __weak typeof(self) weakSelf = self;
    [weakSelf.utils setUpSyncKeyStorageWithPassword:self.password identity:self.eThree.identity completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);
        [syncKeyStorage deleteAllEntriesWithCompletion:^(NSError *error) {
            XCTAssert(error == nil);

            sleep(1);

            [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
                XCTAssert(error == nil);

                NSError *err;
                VSSKeychainEntry *keychainEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
                XCTAssert(err == nil && keychainEntry != nil);

                NSDictionary *dict = keychainEntry.meta;
                NSString *isPublished = dict[@"isPublished"];

                XCTAssert(isPublished.boolValue == true);

                VSSKeychainEntry *syncEntry = [syncKeyStorage retrieveEntryWithName:self.eThree.identity error:&err];
                XCTAssert(err == nil && keychainEntry != nil);
                XCTAssert([syncEntry.data isEqualToData:keychainEntry.data]);

                [self.eThree.cardManager searchCardsWithIdentity:self.eThree.identity completion:^(NSArray<VSSCard *> *cards, NSError *error) {
                    XCTAssert(error == nil && cards.firstObject != nil);

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

- (void)test03 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Bootstrap with password should fetch key if it doesn't exists but card does"];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        sleep(1);

        [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
            XCTAssert(error == nil);

            NSError *err;
            VSSKeychainEntry *entry1 = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
            XCTAssert(err == nil);

            [self.eThree logOutAndReturnError:&err];
            XCTAssert(err == nil);

            VSSKeychainEntry *noEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
            XCTAssert(err != nil && noEntry == nil);

            [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
                XCTAssert(error == nil);

                NSError *err;
                VSSKeychainEntry *entry2 = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
                XCTAssert(err == nil);
                XCTAssert([entry2.data isEqualToData:entry1.data]);
                XCTAssert([entry2.meta isEqualToDictionary:entry1.meta]);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test04 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Bootstrap without password should throw error if key doesn't exists but card does"];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        sleep(1);

        [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
            XCTAssert(error == nil);

            NSError *err;
            VSSKeychainEntry *entry1 = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
            XCTAssert(err == nil && entry1 != nil);

            [self.eThree logOutAndReturnError:&err];
            XCTAssert(err == nil);

            VSSKeychainEntry *noEntry = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
            XCTAssert(err != nil && noEntry == nil);

            [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
                XCTAssert(error != nil);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test05 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Bootstrap should publish card if key exists but card doesn't"];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        sleep(1);

        NSError *err;
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];

        VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
        NSData *exportedKey = [exporter exportPrivateKeyWithPrivateKey:keyPair.privateKey error:&err];
        XCTAssert(err == nil);

        NSDictionary *meta = @{ @"isPublished": @"false"};

        VSSKeychainEntry *entry1 = [self.eThree.keychainStorage storeWithData:exportedKey withName:self.eThree.identity meta:meta error:&err];
        XCTAssert(err == nil && entry1 != nil);

        [self.eThree bootstrapWithPassword:nil completion:^(NSError *error) {
            XCTAssert(error == nil);

            NSError *err;
            VSSKeychainEntry *entry2 = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
            XCTAssert(err == nil && entry2 != nil);
            XCTAssert([entry2.data isEqualToData:entry1.data]);

            NSDictionary *dict = entry2.meta;
            NSString *isPublished = dict[@"isPublished"];

            XCTAssert(isPublished.boolValue == true);

            [self.eThree.cardManager searchCardsWithIdentity:self.eThree.identity completion:^(NSArray<VSSCard *> * returnedCards, NSError *error) {
                XCTAssert(error == nil);
                XCTAssert(returnedCards.count == 1);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

- (void)test06 {
    XCTestExpectation *ex = [self expectationWithDescription:@"Bootstrap should publish card if key exists but card doesn't"];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        sleep(1);

        NSError *err;
        VSMVirgilKeyPair *keyPair = [self.crypto generateKeyPairAndReturnError:nil];

        VSMVirgilPrivateKeyExporter *exporter = [[VSMVirgilPrivateKeyExporter alloc] initWithVirgilCrypto:self.crypto password:nil];
        NSData *exportedKey = [exporter exportPrivateKeyWithPrivateKey:keyPair.privateKey error:&err];
        XCTAssert(err == nil);

        NSDictionary *meta = @{ @"isPublished": @"false"};

        VSSKeychainEntry *entry1 = [self.eThree.keychainStorage storeWithData:exportedKey withName:self.eThree.identity meta:meta error:&err];
        XCTAssert(err == nil && entry1 != nil);

        [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
            XCTAssert(error == nil);

            NSError *err;
            VSSKeychainEntry *entry2 = [self.keychainStorage retrieveEntryWithName:self.eThree.identity error:&err];
            XCTAssert(err == nil && entry2 != nil);
            XCTAssert([entry2.data isEqualToData:entry1.data]);

            NSDictionary *dict = entry2.meta;
            NSString *isPublished = dict[@"isPublished"];

            XCTAssert(isPublished.boolValue == true);

            [self.eThree.cardManager searchCardsWithIdentity:self.eThree.identity completion:^(NSArray<VSSCard *> * returnedCards, NSError *error) {
                XCTAssert(error == nil);
                XCTAssert(returnedCards.count == 1);

                [ex fulfill];
            }];
        }];
    }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError *error) {
        if (error != nil)
            XCTFail(@"Expectation failed: %@", error);
    }];
}

@end
