#!/bin/bash
#
# Copyright © 2019 Oracle Corp., Inc.  All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at http://oss.oracle.com/licenses/upl
#

oci_config() {
    /usr/lib/oci-linux-config/oci-dhclient.sh || :
}

oci_restore() {
    :
}
