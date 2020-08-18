//
//  RCTRsaUtils.m
//  RCTCrypto
//
//  Created by Djorkaeff Alexandre Vilela Pereira on 8/18/20.
//  Copyright © 2020 pedrouid. All rights reserved.
//

#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(RCTRsaUtils, NSObject)

RCT_EXTERN_METHOD(importKey:(NSDictionary *)jwk resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
RCT_EXTERN_METHOD(exportKey:(NSString *)pkcs1 resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)

@end
