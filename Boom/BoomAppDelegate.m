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

@implementation BoomAppDelegate

@synthesize window;
@synthesize runbutton;
@synthesize interfacesPopup;
//@synthesize interfaceList;
@synthesize trafficInfo;
@synthesize isRunning;

#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    uint16_t ether_type; /* IP? ARP? RARP? etc */
};

struct sniff_ipX
{
    uint8_t ip_vhl;
};

#define SNIFF_IPX_V(ipx) ntohl((ipx)->ip_vhl >> 4)

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
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

- (void) runButtonClicked:(id)sender
{
    NSMenuItem *item = [interfacesPopup selectedItem];
    NSLog(@"selected item: %@", item.title);
    if (isRunning)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap = pcap_open_live([item.title cStringUsingEncoding: NSISOLatin1StringEncoding],
                                      65535, NO, 1000, errbuf);
        if (pcap == NULL)
        {
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
        
        struct bpf_program prog;
        if (pcap_compile(pcap, &prog, "tcp || udp", YES, 0) != 0)
        {
            [[NSAlert alertWithMessageText: @"Error"
                             defaultButton: @"OK"
                           alternateButton: nil
                               otherButton: nil
                 informativeTextWithFormat: @"pcap_compile error: %s", pcap_geterr(pcap)]
             beginSheetModalForWindow: window
             modalDelegate: nil
             didEndSelector: NULL
             contextInfo: NULL];
            return;
        }
        pcap_setfilter(pcap, &prog);
        
        NSRunLoop *runloop = [NSRunLoop currentRunLoop];
        [runloop performSelector: @selector(performLoop)
                          target: self
                        argument: nil
                           order: 0
                           modes: [NSArray arrayWithObject: (NSString *) kCFRunLoopDefaultMode]];
        
        runbutton.title = @"Run";
        isRunning = NO;
    }
    else
    {
        runbutton.title = @"Stop";
        isRunning = NO;
    }
}

- (void) handlePacketHeader:(const struct pcap_pkthdr *)hdr withData:(const u_char *)data
{
    
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
        
        NSRunLoop *runloop = [NSRunLoop currentRunLoop];
        [runloop performSelector: @selector(performLoop)
                          target: self
                        argument: nil
                           order: 0
                           modes: [NSArray arrayWithObject: (NSString *) kCFRunLoopDefaultMode]];        
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
