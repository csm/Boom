//
//  BoomAppDelegate.m
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import "BoomAppDelegate.h"

#import <Security/Security.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include <pcap/pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "NetworkAddress.h"
#include "TrafficEntry.h"

#ifdef DEBUG
#define Debug(fmt, args...) NSLog(fmt, ##args)
#else
#define Debug(fmt, args...)
#endif

@implementation BoomAppDelegate

@synthesize window;
@synthesize runbutton;
@synthesize interfacesPopup;
@synthesize tableView;
@synthesize trafficInfoController;
@synthesize packetFilterField;
//@synthesize interfaceList;
//@synthesize trafficInfo;
@synthesize isRunning;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    counters = [[NSMutableDictionary alloc] init];
    // Insert code here to initialize your application
}

#pragma mark - Accessors

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
    Debug(@"returning %lu traffic infos", [ret count]);
    return ret;
}

#pragma mark - Actions

- (void) runButtonClicked:(id)sender
{
    NSMenuItem *item = [interfacesPopup selectedItem];
    //Debug(@"selected item: %@", item.title);
    if (!isRunning)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        const char *dev = [item.title cStringUsingEncoding: NSISOLatin1StringEncoding];
        //Debug(@"capture from device %s", dev);
        int ntries = 0;
        while ((pcap = pcap_open_live(dev, 65535, 0, 100, errbuf)) == NULL)
        {
            ntries++;
            if (ntries < 2)
            {
                Debug(@"Attempting to change /dev/bpf* permissions");
                AuthorizationRef auth;
                OSStatus retval;
                retval = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
                                             kAuthorizationFlagDefaults, &auth);
                if (retval != errAuthorizationSuccess)
                {
                    Debug(@"AuthorizationCreate: %d", retval);
                    AuthorizationFree(auth, kAuthorizationFlagDestroyRights);
                    continue;
                }
                
                AuthorizationItem authItem = { kAuthorizationRightExecute, 0, NULL, 0 };
                AuthorizationRights authRights = { 1, &authItem };
                AuthorizationFlags flags = (kAuthorizationFlagDefaults |
                                            kAuthorizationFlagInteractionAllowed |
                                            kAuthorizationFlagPreAuthorize |
                                            kAuthorizationFlagExtendRights);
                retval = AuthorizationCopyRights(auth, &authRights, NULL, flags, NULL);
                if (retval != errAuthorizationSuccess)
                {
                    Debug(@"AuthorizationCopyRights: %d", retval);
                    AuthorizationFree(auth, kAuthorizationFlagDestroyRights);
                    continue;
                }
                
                NSFileManager *fm = [NSFileManager defaultManager];
                NSError *error = nil;
                NSArray *files = [fm contentsOfDirectoryAtPath: @"/dev"
                                                         error: &error];
                if (files == nil)
                {
                    
                }
                for (NSString *file in files)
                {
                    if ([file hasPrefix: @"bpf"])
                    {
                        NSString *path = [@"/dev" stringByAppendingPathComponent: file];
                        const char *program = "/bin/chmod";
                        char * const args[] = { "644", (char *) [path cStringUsingEncoding: NSASCIIStringEncoding], NULL };
                        FILE *pipe = NULL;
                
                        retval = AuthorizationExecuteWithPrivileges(auth, program, kAuthorizationFlagDefaults, args, &pipe);
                        if (retval != errAuthorizationSuccess)
                            Debug(@"execute /bin/chmod 644 %@ failed: %d", path, retval);
                    }
                }
                AuthorizationFree(auth, kAuthorizationFlagDestroyRights);
                
                continue;
            }
            Debug(@"pcap_open_live: %s", errbuf);
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
        //pcap_set_buffer_size(pcap, 65535);
        //pcap_set_timeout(pcap, 100);
        //pcap_set_promisc(pcap, 0);
        
        NSString *filter = [[packetFilterField stringValue] stringByTrimmingCharactersInSet: [NSCharacterSet whitespaceCharacterSet]];
        if (filter == nil || [filter length] == 0)
            filter = @"tcp || udp";
        
        /*if (pcap_activate(pcap) != 0)
        {
            Debug(@"pcap_activate: %s", pcap_geterr(pcap));
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
        }*/

        struct bpf_program prog;
        Debug(@"using filter %@", filter);
        if (pcap_compile(pcap, &prog, [filter cStringUsingEncoding: NSISOLatin1StringEncoding], YES, PCAP_NETMASK_UNKNOWN) != 0)
        {
            Debug(@"pcap_compile: %s", pcap_geterr(pcap));
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
        int ret = pcap_setfilter(pcap, &prog);
        Debug(@"pcap_setfilter returned %d", ret);
        if (ret < 0)
        {
            Debug(@"pcap_setfilter: %s", pcap_geterr(pcap));
            [[NSAlert alertWithMessageText: @"Error"
                             defaultButton: @"OK"
                           alternateButton: nil
                               otherButton: nil
                 informativeTextWithFormat: @"pcap_setfilter error: %s", pcap_geterr(pcap)]
             beginSheetModalForWindow: window
             modalDelegate: nil
             didEndSelector: NULL
             contextInfo: NULL];
            pcap_close(pcap);
            pcap = NULL;
            return;            
        }
        
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
        
        loopTimer = [NSTimer scheduledTimerWithTimeInterval: 0.1
                                                     target: self
                                                   selector: @selector(performLoop)
                                                   userInfo: nil
                                                    repeats: YES];
        [loopTimer retain];

        runbutton.title = @"Stop";
        isRunning = YES;
    }
    else
    {
        if (loopTimer != nil)
        {
            [loopTimer invalidate];
            [loopTimer release];
            loopTimer = nil;
        }
        runbutton.title = @"Run";
        isRunning = NO;
    }
}

- (IBAction) clearButtonClicked:(id)sender
{
    [counters removeAllObjects];
    [trafficInfoController setContent: [self trafficInfo]];
}

#pragma mark - Packet handling

- (void) handlePacketHeader:(const struct pcap_pkthdr *)hdr withData:(const u_char *)data
{
    struct ether_header *ether = (struct ether_header *) data;
#ifdef DEBUG
    Debug(@"capture: %ld %u %u 0x%x", hdr->ts.tv_sec, hdr->caplen, hdr->len, ether->ether_type);
#endif
    if (ntohs(ether->ether_type) == ETHERTYPE_IP)
    {
        struct ip *ip = (struct ip *) (data + sizeof(struct ether_header));
#ifdef DEBUG
        Debug(@"  IPv4, %d %d %x", ip->ip_v, ip->ip_hl, ip->ip_p);
#endif
        if (ip->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *) (data + sizeof(struct ether_header) + (ip->ip_hl*4));
#ifdef DEBUG
            Debug(@"  TCP %d %d", tcp->th_sport, tcp->th_dport);
#endif
            if (memcmp(&ip->ip_dst, &inaddr, sizeof(struct in_addr)) == 0)
            {
                //Debug(@"  received packet");
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP4Address: ip->ip_src
                                                                             port: tcp->th_sport
                                                                       socketType: IPPROTO_TCP];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                    [entry release];
                }
                entry._bytesIn += hdr->len - sizeof(struct ether_header) - (ip->ip_hl*4) - (tcp->th_off*4);
                [addr release];
            }
            else if (memcmp(&ip->ip_src, &inaddr, sizeof(struct in_addr)) == 0)
            {
                //Debug(@"  sent packet");
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP4Address: ip->ip_dst
                                                                             port: tcp->th_dport
                                                                       socketType: IPPROTO_TCP];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                    [entry release];
                }
                entry._bytesOut += hdr->len - sizeof(struct ether_header) - (ip->ip_hl*4) - (tcp->th_off*4);
                [addr release];
            }
        }
        if (ip->ip_p == IPPROTO_UDP)
        {
            //Debug(@"  UDP");
            struct udphdr *udp = (struct udphdr *) (data + sizeof(struct ether_header) + (ip->ip_hl*4));
            if (memcmp(&ip->ip_dst, &inaddr, sizeof(struct in_addr)) == 0)
            {
                //Debug(@"  received packet");
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP4Address: ip->ip_src
                                                                             port: udp->uh_sport
                                                                       socketType: IPPROTO_UDP];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                    [entry release];
                }
                entry._bytesIn += hdr->len - sizeof(struct ether_header) - (ip->ip_hl*4) - 8;
                [addr release];
            }
            else if (memcmp(&ip->ip_src, &inaddr, sizeof(struct in_addr)) == 0)
            {
                //Debug(@"  sent packet");
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP4Address: ip->ip_dst
                                                                             port: udp->uh_dport
                                                                       socketType: IPPROTO_UDP];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                    [entry release];
                }
                entry._bytesOut += hdr->len - sizeof(struct ether_header) - (ip->ip_hl*4) - 8;
                [addr release];
            }
        }
    }
    else if (ntohs(ether->ether_type) == ETHERTYPE_IPV6)
    {
        struct ip6_hdr *ip6 = (struct ip6_hdr *) (data + sizeof(struct ether_header));
        unsigned long hdrlen = hdr->len - sizeof(struct ether_header) - ip6->ip6_ctlun.ip6_un1.ip6_un1_plen;
        if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
        {
            struct tcphdr *tcp = (struct tcphdr *) (data + sizeof(struct ether_header) + hdrlen);
            if (memcmp(&ip6->ip6_dst, &in6addr, sizeof(struct in6_addr)) == 0)
            {
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP6Address: ip6->ip6_src
                                                                             port: tcp->th_sport
                                                                       socketType: IPPROTO_TCP];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                    [entry release];
                }
                entry._bytesIn += ip6->ip6_ctlun.ip6_un1.ip6_un1_plen - (tcp->th_off*4);
                [addr release];
            }
            else if (memcmp(&ip6->ip6_src, &in6addr, sizeof(struct in6_addr)) == 0)
            {
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP6Address: ip6->ip6_dst
                                                                             port: tcp->th_dport
                                                                       socketType: IPPROTO_TCP];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                    [entry release];
                }
                entry._bytesOut += ip6->ip6_ctlun.ip6_un1.ip6_un1_plen - (tcp->th_off*4);
                [addr release];                
            }
        }
        else if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP)
        {
            struct udphdr *udp = (struct udphdr *) (data + sizeof(struct ether_header) + hdrlen);
            if (memcmp(&ip6->ip6_dst, &in6addr, sizeof(struct in6_addr)) == 0)
            {
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP6Address: ip6->ip6_src
                                                                             port: udp->uh_sport
                                                                       socketType: IPPROTO_UDP];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                    [entry release];
                }
                entry._bytesIn += ip6->ip6_ctlun.ip6_un1.ip6_un1_plen - 8;
                [addr release];
            }
            else if (memcmp(&ip6->ip6_src, &in6addr, sizeof(struct in6_addr)) == 0)
            {
                NetworkAddress *addr = [[NetworkAddress alloc] initWithIP6Address: ip6->ip6_dst
                                                                             port: udp->uh_dport
                                                                       socketType: IPPROTO_UDP];
                TrafficEntry *entry = [counters objectForKey: addr];
                if (entry == nil)
                {
                    entry = [[TrafficEntry alloc] initWithAddress: addr];
                    [counters setObject: entry forKey: addr];
                    [entry release];
                }
                entry._bytesOut += ip6->ip6_ctlun.ip6_un1.ip6_un1_plen - 8;
                [addr release];
            }
        }   
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
