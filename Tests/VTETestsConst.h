//
//  VTETestsConsts.h
//  VirgilE3Kit
//
//  Created by Eugen Pivovarov on 10/19/18.
//

#ifndef VTETestsConst_h
#define VTETestsConst_h

#import <Foundation/Foundation.h>

//In order to make this work, substitute appropriate values
@interface VTETestsConst : NSObject

@property (nonatomic, readonly) NSString * __nonnull apiPublicKeyId;
@property (nonatomic, readonly) NSString * __nonnull apiPrivateKeyBase64;
@property (nonatomic, readonly) NSString * __nonnull applicationId;
@property (nonatomic, readonly) NSURL * __nullable serviceURL;
@property (nonatomic, readonly) NSString * __nullable servicePublicKey;

@property (nonatomic, readonly) NSDictionary * __nonnull config;

@end

#endif /* VTETestsConst_h */
