//
//  VTETestsConsts.m
//  VirgilE3Kit
//
//  Created by Eugen Pivovarov on 10/19/18.
//

#define STRINGIZE(x) #x
#define STRINGIZE2(x) STRINGIZE(x)

#import "VTETestsConst.h"

@implementation VTETestsConst

- (instancetype)init
{
    self = [super init];
    if (self) {
        NSBundle *bundle = [NSBundle bundleForClass:self.class];
        NSURL *configFileUrl = [bundle URLForResource:@"TestConfig" withExtension:@"plist"];
        NSDictionary *config = [NSDictionary dictionaryWithContentsOfURL:configFileUrl];
        _config = config;
    }

    return self;
}

- (NSString *)apiPublicKeyId {
    NSString *appToken = self.config[@"ApiPublicKeyId"];

    return appToken;
}

- (NSString *)apiPrivateKeyBase64 {
    NSString *appPrivateKey = self.config[@"ApiPrivateKey"];

    return appPrivateKey;
}

- (NSString *)applicationId {
    NSString *appId = self.config[@"AppId"];

    return appId;
}

- (NSURL *)serviceURL {
    NSString *cardsUrl = self.config[@"ServiceURL"];
    if (cardsUrl != nil)
        return [[NSURL alloc] initWithString:cardsUrl];

    return nil;
}

- (NSString *)servicePublicKey {
    NSString *servicePublicKey = self.config[@"ServicePublicKey"];

    return servicePublicKey;
}

@end
