#!/bin/bash

#  gen-infoplist.sh
#  Boom
#
#  Created by Casey Marshall on 7/28/11.
#  Copyright 2011 Memeo, Inc. All rights reserved.

SHORT_VERSION=`git describe --always | sed 's/-.*$//'`
BUNDLE_VERSION=`git describe --always`

sed "s/@@SHORT_VERSION@@/${SHORT_VERSION}/" ${SRCROOT}/Boom/Boom-Info-in.plist | sed "s/@@BUNDLE_VERSION@@/${BUNDLE_VERSION}/" > ${SRCROOT}/Boom/Boom-Info.plist