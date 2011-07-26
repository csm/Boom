//
//  TrafficEntry.h
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "NetworkAddress.h"

@interface TrafficEntry : NSObject {
    NetworkAddress *address;
    unsigned long long _bytesIn;
    unsigned long long _bytesOut;
}

- (id) initWithAddress: (NetworkAddress *) addr;

@property (nonatomic, readwrite, retain) NetworkAddress *address;
@property (nonatomic, readonly) NSString *hostname;
@property (nonatomic, readonly) NSString *protocol;
@property (nonatomic, readonly) NSNumber *port;
@property (nonatomic, readonly) NSNumber *bytesIn;
@property (nonatomic, readonly) NSNumber *bytesOut;

@property (nonatomic, assign) unsigned long long _bytesIn;
@property (nonatomic, assign) unsigned long long _bytesOut;

@end

