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

@implementation VTETestBase

- (void)setUp {
    [super setUp];

    self.password = [[NSUUID alloc] init].UUIDString;
    self.utils = [[VTETestUtils alloc] init];
    self.consts = self.utils.config;
    self.crypto = self.utils.crypto;

    VSSKeychainStorageParams *params;
#if TARGET_OS_IOS || TARGET_OS_TV
    params = [VSSKeychainStorageParams makeKeychainStorageParamsWithAppName:@"test" error:nil];
#elif TARGET_OS_OSX
    params = [VSSKeychainStorageParams makeKeychainStorageParamsWithAppName:@"test" error:nil];
#endif
    self.keychainStorage = [[VSSKeychainStorage alloc] initWithStorageParams:params];
    [self.keychainStorage deleteAllEntriesWithQueryOptions:nil error:nil];

    NSError *error;
    NSString *identity = [[NSUUID alloc] init].UUIDString;
    
    VTEEThreeParams *e3Params = [[VTEEThreeParams alloc] initWithIdentity:identity
                                                          tokenCallback:^(void (^completionHandler)(NSString *, NSError *)) {
        NSString *token = [self.utils getTokenStringWithIdentity:identity];
        completionHandler(token, nil);
    }];
    
    e3Params.keyPairType = VSMKeyPairTypeEd25519;
    e3Params.storageParams = params;
    
    NSURL *serviceUrl = [[NSURL alloc] initWithString:self.consts.ServiceURL];
    
    VTEServiceUrls *serviceUrls = [[VTEServiceUrls alloc] initWithCardServiceUrl:serviceUrl
                                                                pythiaServiceUrl:serviceUrl
                                                               keyknoxServiceUrl:serviceUrl
                                                               ratchetServiceUrl:serviceUrl];
    
    e3Params.serviceUrls = serviceUrls;
    e3Params.overrideVirgilPublicKey = self.consts.ServicePublicKey;
    
    self.eThree = [[VTEEThree alloc] initWithParams:e3Params error:&error];
    XCTAssert(self.eThree != nil && error == nil);
}

@end
