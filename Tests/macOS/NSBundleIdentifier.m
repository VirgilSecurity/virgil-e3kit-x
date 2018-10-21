//
//  NSBundleIdentifier.m
//  VirgilE3Kit macOS Tests
//
//  Created by Eugen Pivovarov on 10/20/18.
//

#import <Foundation/Foundation.h>

@implementation NSBundle (BundleIdentifier)

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"
-(NSString *)bundleIdentifier
{
    return @"com.virgilsecurity.e3kit.unitTests";
}
#pragma clang diagnostic pop

@end
