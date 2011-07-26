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

- (NSString *) protocol
{
    if (address.socketType == IPPROTO_UDP)
        return @"UDP";
    if (address.socketType == IPPROTO_TCP)
        return @"TCP";
    return @"???";
}

- (NSNumber *) port
{
    return [NSNumber numberWithInt: address.port];
}

- (NSNumber *) bytesIn
{
    return [NSNumber numberWithUnsignedLongLong: _bytesIn];
}

- (NSNumber *) bytesOut
{
    return [NSNumber numberWithUnsignedLongLong: _bytesOut];
}

- (void) dealloc
{
    [address release];
    [super dealloc];
}

@end
