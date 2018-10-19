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

    NSError *error;
    [self.keychainStorage deleteAllEntriesAndReturnError:&error];

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
    XCTestExpectation *ex = [self expectationWithDescription:@"Bootstrap should create local key and publish card"];

    NSError *error;
    [self.keychainStorage deleteAllEntriesAndReturnError:&error];

    [self.utils clearAllStoragesWithPassword:self.password identity:self.eThree.identity keychainStorage:self.keychainStorage completionHandler:^(VSKSyncKeyStorage *syncKeyStorage, NSError *error) {
        XCTAssert(error == nil);

        sleep(1);

        [self.eThree bootstrapWithPassword:self.password completion:^(NSError *error) {
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

@end
