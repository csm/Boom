//
//  TrafficEntry.m
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import "TrafficEntry.h"

@implementation TrafficEntry

@synthesize hostname, protocol, bytesIn, bytesOut;

- (id)init
{
    self = [super init];
    if (self) {
        // Initialization code here.
    }
    
    return self;
}

- (void) dealloc
{
    [hostname release];
    [protocol release];
    [super dealloc];
}

@end
