//
//  VTETestsUtils.h
//  VirgilE3Kit
//
//  Created by Eugen Pivovarov on 10/19/18.
//

#ifndef VTETestUtils_h
#define VTETestUtils_h

#import "VTETestsConst.h"

@import VirgilSDK;
@import VirgilCryptoApiImpl;

@interface VTETestUtils : NSObject

@property (nonatomic) VSMVirgilCrypto * __nonnull crypto;
@property (nonatomic) VTETestsConst * __nonnull consts;

- (NSString * __nonnull)getTokenStringWithIdentity:(NSString * __nonnull)identity error:(NSError * __nullable * __nullable)errorPtr;
- (id<VSSAccessToken> __nonnull)getTokenWithIdentity:(NSString * __nonnull)identity ttl:(NSTimeInterval)ttl error:(NSError * __nullable * __nullable)errorPtr;
- (VSSCard * __nullable)publishRandomCard;
- (BOOL)isPublicKeysEqualWithPublicKeys1:(NSArray <VSMVirgilPublicKey *> * __nonnull)publicKeys1 publicKeys2:(NSArray <VSMVirgilPublicKey *> * __nonnull)publicKeys2;

- (instancetype __nonnull)initWith NS_UNAVAILABLE;

- (instancetype __nonnull)initWithCrypto:(VSMVirgilCrypto * __nonnull)crypto consts:(VTETestsConst * __nonnull)consts;

@end


#endif /* VTETestUtils_h */
