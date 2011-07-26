//
//  BoomAppDelegate.h
//  Boom
//
//  Created by Casey Marshall on 7/25/11.
//  Copyright 2011 Memeo, Inc. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#include <pcap/pcap.h>

@interface BoomAppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate> {
    NSWindow *window;
    NSArray *interfaceList;
    NSArray *trafficInfo;
    NSButton *runbutton;
    NSPopUpButton *interfacesPopup;
    BOOL isRunning;
    pcap_t *pcap;
}

@property (assign) IBOutlet NSWindow *window;
@property (assign) IBOutlet NSButton *runbutton;
@property (assign) IBOutlet NSPopUpButton *interfacesPopup;

//@property (readonly) IBOutlet NSArray *interfaceList;
@property (readonly) IBOutlet NSArray *trafficInfo;
@property (readonly) BOOL isRunning;

- (NSArray *) interfaceList;

- (IBAction) runButtonClicked: (id) sender;

- (void) performLoop;
- (void) handlePacketHeader: (const struct pcap_pkthdr *) hdr
                   withData: (const u_char *) data;

@end
