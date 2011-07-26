//
//  BoomAppDelegate.h
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#include <pcap/pcap.h>
#include <netinet/in.h>

@interface BoomAppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate> {
    NSWindow *window;
    NSArray *interfaceList;
    NSArray *trafficInfo;
    NSButton *runbutton;
    NSPopUpButton *interfacesPopup;
    NSTableView *tableView;
    NSTextField *packetFilterField;
    BOOL isRunning;
    pcap_t *pcap;
    NSMutableDictionary *counters;
    NSTimer *loopTimer;
    
    NSArrayController *trafficInfoController;
    
    struct in_addr inaddr;
    struct in6_addr in6addr;
}

@property (assign) IBOutlet NSWindow *window;
@property (assign) IBOutlet NSButton *runbutton;
@property (assign) IBOutlet NSPopUpButton *interfacesPopup;
@property (assign) IBOutlet NSTableView *tableView;
@property (assign) IBOutlet NSArrayController *trafficInfoController;
@property (assign) IBOutlet NSTextField *packetFilterField;

//@property (readonly) IBOutlet NSArray *interfaceList;
@property (readonly) IBOutlet NSArray *trafficInfo;
@property (readonly) BOOL isRunning;

- (NSArray *) interfaceList;

- (IBAction) runButtonClicked: (id) sender;
- (IBAction) clearButtonClicked: (id) sender;

- (void) performLoop;
- (void) handlePacketHeader: (const struct pcap_pkthdr *) hdr
                   withData: (const u_char *) data;

@end
