//
//  NetworkAddress.m
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import "NetworkAddress.h"

#include <arpa/inet.h>

@implementation NetworkAddress

- (id) initWithSocketAddress: (const struct sockaddr *) addr
                  socketType: (int) type
{
    self = [super init];
    if (self)
    {
        if (addr->sa_family == AF_INET)
        {
            memcpy(&address.s_in4, addr, sizeof(struct sockaddr_in));
        }
        else if (addr->sa_family == AF_INET6)
        {
            memcpy(&address.s_in6, addr, sizeof(struct sockaddr_in6));
        }
        else
        {
            memset(&address.s_addr, 0, sizeof(struct sockaddr));
        }
        if (type == IPPROTO_UDP || type == IPPROTO_TCP)
            socketType = type;
        else
            socketType = -1;
    }
    
    return self;
}

- (id) initWithIP4Address:(struct in_addr)addr port:(uint16_t)port
               socketType:(int)type
{
    struct sockaddr_in in4;
    memset(&in4, 0, sizeof(struct sockaddr_in));
    in4.sin_family = AF_INET;
    memcpy(&in4.sin_addr, &addr, sizeof(struct in_addr));
    in4.sin_port = port;
    return [self initWithSocketAddress: (const struct sockaddr *) &in4
                            socketType: type];
}

- (id) initWithIP6Address:(struct in6_addr)addr port:(uint16_t)port
               socketType:(int)type
{
    struct sockaddr_in6 in6;
    memset(&in6, 0, sizeof(struct sockaddr_in6));
    in6.sin6_family = AF_INET6;
    memcpy(&in6.sin6_addr, &addr, sizeof(struct in6_addr));
    in6.sin6_port = port;
    return [self initWithSocketAddress: (const struct sockaddr *) &in6
                            socketType: type];
}

- (int) family
{
    return address.s_addr.sa_family;
}

- (int) socketType
{
    return socketType;
}

- (int) port
{
    if (self.family == AF_INET)
        return ntohs(address.s_in4.sin_port);
    if (self.family == AF_INET6)
        return ntohs(address.s_in6.sin6_port);
    return -1;
}

- (NSString *) addressName
{
    if (self.family == AF_INET)
    {
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &address.s_in4.sin_addr, buf, INET_ADDRSTRLEN) != NULL)
            return [NSString stringWithCString: buf
                                      encoding: NSISOLatin1StringEncoding];
        return nil;
    }
    if (self.family == AF_INET6)
    {
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &address.s_in6.sin6_addr, buf, INET6_ADDRSTRLEN) != NULL)
            return [NSString stringWithCString: buf
                                      encoding: NSISOLatin1StringEncoding];
    }
    return nil;
}

- (struct sockaddr_in) in4
{
    return address.s_in4;
}

- (struct sockaddr_in6) in6
{
    return address.s_in6;
}

- (NSUInteger) hash
{
    if (self.family == AF_INET)
        return [self.addressName hash] ^ address.s_in4.sin_port ^ socketType;
    if (self.family == AF_INET6)
        return [self.addressName hash] ^ address.s_in6.sin6_port ^ socketType;
    return 0;
}

- (BOOL) isEqual:(id)object
{
    if ([object isKindOfClass: [NetworkAddress class]])
    {
        NetworkAddress *that = (NetworkAddress *) object;
        if (self.family == that.family && self.socketType == that.socketType)
        {
            if (self.family == AF_INET)
            {
                struct sockaddr_in a = that.in4;
                return (memcmp(&a, &address.s_in4, sizeof(struct sockaddr_in)) == 0);
            }
            if (self.family == AF_INET6)
            {
                struct sockaddr_in6 a = that.in6;
                return (memcmp(&a, &address.s_in6, sizeof(struct sockaddr_in6)) == 0);
            }
        }
    }
    return NO;
}

- (id) copyWithZone:(NSZone *)zone
{
    NetworkAddress *ret = [[NetworkAddress allocWithZone: zone] initWithSocketAddress: &address.s_addr socketType: socketType];
    return ret;
}

@end
