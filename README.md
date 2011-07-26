This is a little program for OS X for tracking the _amount_ of traffic that goes to and from remote hosts. It uses `libpcap` to capture traffic on a network interface.

It requires permission to access the `/dev/bpf*` interfaces. You can grant access by doing:

    sudo chmod 644 /dev/bpf*

You may have to do this every time you reboot.

We aren't that interested in making this program any better than it is; it was a one-off hack for a demo.