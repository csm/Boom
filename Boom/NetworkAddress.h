//
//  NetworkAddress.h
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <sys/socket.h>
#include <netinet/in.h>

@interface NetworkAddress : NSObject <NSCopying>
{
    union
    {
        struct sockaddr s_addr;
        struct sockaddr_in s_in4;
        struct sockaddr_in6 s_in6;
    } address;
    int socketType;
}

@property (readonly) int family;
@property (readonly) int port;
@property (assign) int socketType;

@property (readonly) struct sockaddr_in in4;
@property (readonly) struct sockaddr_in6 in6;

@property (readonly) NSString *addressName;

- (id) initWithSocketAddress: (const struct sockaddr *) addr
                  socketType: (int) socketType;
- (id) initWithIP4Address: (struct in_addr) addr
                     port: (uint16_t) port
               socketType: (int) socketType;
- (id) initWithIP6Address: (struct in6_addr) addr
                     port: (uint16_t) port
               socketType: (int) socketType;

@end
