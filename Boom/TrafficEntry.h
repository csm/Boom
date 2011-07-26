//
//  TrafficEntry.h
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TrafficEntry : NSObject {
    NSString *hostname;
    NSString *protocol;
    NSNumber *bytesIn;
    NSNumber *bytesOut;
}

@property (nonatomic, readwrite, retain) NSString *hostname;
@property (nonatomic, readwrite, retain) NSString *protocol;
@property (nonatomic, readwrite, retain) NSNumber *bytesIn;
@property (nonatomic, readwrite, retain) NSNumber *bytesOut;

@end

