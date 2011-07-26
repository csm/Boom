//
//  TrafficEntry.m
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import "TrafficEntry.h"

@implementation TrafficEntry

@synthesize address, _bytesIn, _bytesOut;

- (id) initWithAddress:(NetworkAddress *)addr
{
    self = [super init];
    if (self)
    {
        address = addr;
        [address retain];
    }
    
    return self;
}

- (NSString *) hostname
{
    return address.addressName;
}

- (NSString *) port
{
    return [NSString stringWithFormat: @"%d", address.port];
}

- (NSString *) bytesIn
{
    return [NSString stringWithFormat: @"%llu", _bytesIn];
}

- (NSString *) bytesOut
{
    return [NSString stringWithFormat: @"%llu", _bytesOut];
}

- (void) dealloc
{
    [address release];
    [super dealloc];
}

@end
