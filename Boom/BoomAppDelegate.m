//
//  BoomAppDelegate.m
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import "BoomAppDelegate.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include <pcap/pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "NetworkAddress.h"
#include "TrafficEntry.h"

@implementation BoomAppDelegate

@synthesize window;
@synthesize runbutton;
@synthesize interfacesPopup;
@synthesize tableView;
@synthesize trafficInfoController;
//@synthesize interfaceList;
//@synthesize trafficInfo;
@synthesize isRunning;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    counters = [[NSMutableDictionary alloc] init];
    // Insert code here to initialize your application
}

- (NSArray *) interfaceList
{
    if (interfaceList == nil)
    {
        struct ifaddrs *ifaddrs;
        if (getifaddrs(&ifaddrs) == 0)
        {
            NSMutableArray *a = [NSMutableArray arrayWithCapacity: 5];
            struct ifaddrs *i = ifaddrs;
            while (i != NULL)
            {
                NSString *name = [NSString stringWithCString: i->ifa_name
                                                    encoding: NSISOLatin1StringEncoding];
                if (![a containsObject: name])
                    [a addObject: name];
                i = i->ifa_next;
            }
            interfaceList = [[NSArray alloc] initWithArray: a];
        }
        else
            interfaceList = [[NSArray alloc] init];
    }
    return interfaceList;
}

- (NSArray *) trafficInfo
{
    NSArray *ret = [counters allValues];
    NSLog(@"returning %lu traffic infos", [ret count]);
    return ret;
}

- (void) runButtonClicked:(id)sender
{
    NSMenuItem *item = [interfacesPopup selectedItem];
    //NSLog(@"selected item: %@", item.title);
    if (!isRunning)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        const char *dev = [item.title cStringUsingEncoding: NSISOLatin1StringEncoding];
        //NSLog(@"capture from device %s", dev);
        pcap = pcap_create(dev, errbuf);
        if (pcap == NULL)
        {
            NSLog(@"pcap_open_live: %s", errbuf);
            [[NSAlert alertWithMessageText: @"Error"
                             defaultButton: @"OK"
                           alternateButton: nil
                               otherButton: nil
                 informativeTextWithFormat: @"libpcap error: %s", errbuf]
             beginSheetModalForWindow: window
                        modalDelegate: nil
                       didEndSelector: NULL
                          contextInfo: NULL];
            return;
        }
        pcap_set_buffer_size(pcap, 65535);
        pcap_set_timeout(pcap, 100);
        pcap_set_promisc(pcap, 0);
        if (pcap_activate(pcap) != 0)
        {
            NSLog(@"pcap_activate: %s", pcap_geterr(pcap));
            [[NSAlert alertWithMessageText: @"Error"
                             defaultButton: @"OK"
                           alternateButton: nil
                               otherButton: nil
                 informativeTextWithFormat: @"pcap_activate error: %s", pcap_geterr(pcap)]
             beginSheetModalForWindow: window
             modalDelegate: nil
             didEndSelector: NULL
             contextInfo: NULL];
            pcap_close(pcap);
            pcap = NULL;
            return;
        }
        
        struct bpf_program prog;
        if (pcap_compile(pcap, &prog, "tcp || udp", YES, 0) != 0)
        {
            NSLog(@"pcap_compile: %s", pcap_geterr(pcap));
            [[NSAlert alertWithMessageText: @"Error"
                             defaultButton: @"OK"
                           alternateButton: nil
                               otherButton: nil
                 informativeTextWithFormat: @"pcap_compile error: %s", pcap_geterr(pcap)]
             beginSheetModalForWindow: window
             modalDelegate: nil
             didEndSelector: NULL
             contextInfo: NULL];
            pcap_close(pcap);
            pcap = NULL;
            return;
        }
        pcap_setfilter(pcap, &prog);
        
        memset(&inaddr, 0xFF, sizeof(struct in_addr));
        memset(&in6addr, 0xFF, sizeof(struct in6_addr));
        struct ifaddrs *ifaddrs;
        if (getifaddrs(&ifaddrs) == 0)
        {
            for (struct ifaddrs *i = ifaddrs; i != NULL; i = i->ifa_next)
            {
                if (strcmp(dev, i->ifa_name) == 0)
                {
                    if (i->ifa_addr->sa_family == AF_INET)
                        memcpy(&inaddr, &((struct sockaddr_in *) i->ifa_addr)->sin_addr, sizeof(struct in_addr));
                    if (i->ifa_addr->sa_family == AF_INET6)
                        memcpy(&in6addr, &((struct sockaddr_in6 *) i->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
                }
            }
        }
        
        NSRunLoop *runloop = [NSRunLoop currentRunLoop];
        [runloop performSelector: @selector(performLoop)
                          target: self
                        argument: nil
                           order: 0
                           modes: [NSArray arrayWithObject: NSRunLoopCommonModes]];
        
        runbutton.title = @"Stop";
        isRunning = YES;
    }
    else
    {
        runbutton.title = @"Run";
        isRunning = NO;
    }
}

- (void) handlePacketHeader:(const struct pcap_pkthdr *)hdr withData:(const u_char *)data
{
    struct ether_header *ether = (struct ether_header *) data;
    NSLog(@"capture: %ld %u %u 0x%x", hdr->ts.tv_sec, hdr->caplen, hdr->len, ether->ether_type);
    if (ntohs(ether->ether_type) == ETHERTYPE_IP)
    {
        struct ip *ip = (struct ip *) (data + sizeof(struct ether_header));
        //NSLog(@"  IPv4, %x", ip->ip_p);
        if (ip->ip_p == IPPROTO_TCP)
        {
            //NSLog(@"  TCP");
            struct tcphdr *tcp = (struct tcphdr *) (data + sizeof(struct ether_header) + (ip->ip_hl*32));
            if (memcmp(&ip->ip_dst, &inaddr, sizeof(struct in_addr)) == 0)
            {
                //NSLog(@"  received packet");
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP4Address: ip->ip_src
                                                                             port: tcp->th_sport];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                }
                entry._bytesIn += 1;
            }
            else if (memcmp(&ip->ip_src, &inaddr, sizeof(struct in_addr)) == 0)
            {
                //NSLog(@"  sent packet");
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP4Address: ip->ip_dst
                                                                             port: tcp->th_dport];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                }
                entry._bytesOut += 1;
            }
        }
        if (ip->ip_p == IPPROTO_UDP)
        {
            //NSLog(@"  UDP");
            struct udphdr *udp = (struct udphdr *) (data + sizeof(struct ether_header) + (ip->ip_hl*32));
            if (memcmp(&ip->ip_dst, &inaddr, sizeof(struct in_addr)) == 0)
            {
                //NSLog(@"  received packet");
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP4Address: ip->ip_src
                                                                             port: udp->uh_sport];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                }
                entry._bytesIn += 1;
            }
            else if (memcmp(&ip->ip_src, &inaddr, sizeof(struct in_addr)) == 0)
            {
                //NSLog(@"  sent packet");
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP4Address: ip->ip_dst
                                                                             port: udp->uh_dport];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                }
                entry._bytesOut += 1;
            }
        }
    }
    else if (ntohs(ether->ether_type) == ETHERTYPE_IPV6)
    {
    }
}

static void handle_pcap(u_char *user, const struct pcap_pkthdr *hdr, const u_char *bytes)
{
    BoomAppDelegate *self = (BoomAppDelegate *) user;
    [self handlePacketHeader: hdr withData: bytes];
}

- (void) performLoop
{
    if (isRunning && pcap != NULL)
    {
        pcap_dispatch(pcap, 20, handle_pcap, (u_char *) self);
        //[tableView reloadData];
        [trafficInfoController setContent: [self trafficInfo]];
        NSRunLoop *runloop = [NSRunLoop currentRunLoop];
        [runloop performSelector: @selector(performLoop)
                          target: self
                        argument: nil
                           order: 0
                           modes: [NSArray arrayWithObject: NSRunLoopCommonModes]];    
    }
    else
    {
        pcap_close(pcap);
        pcap = NULL;
    }
}

- (BOOL) windowShouldClose:(id)sender
{
    [[NSApplication sharedApplication] terminate: self];
    return YES;
}

@end
