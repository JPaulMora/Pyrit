# -*- coding: UTF-8 -*-
#
#    Copyright 2008-2010, Lukas Lueg, lukas.lueg@gmail.com
#
#    This file is part of Pyrit.
#
#    Pyrit is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Pyrit is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Pyrit.  If not, see <http://www.gnu.org/licenses/>.

""" This modules deals with parsing of IEEE802.11-packets and attacking
    EAPOL-authentications.

    Scapy's Packet-class is extended with some utility-functions as described.

    The class PacketParser can be used to analyze a (possibly gzip-compressed)
    packet-capture-file in pcap-format. The representation gained from it is
    not exact in the strictest sense but a straightforward hierarchy of
    AccessPoint -> Station -> EAPOLAuthentication.
"""

import threading
import Queue

import util
import _cpyrit_cpu

try:
    import scapy.config
    scapy.config.conf.logLevel = 40 # Suppress useless warnings from scapy...
    import scapy.fields
    import scapy.layers.dot11
    import scapy.packet
    import scapy.utils
except ImportError, e:
    raise util.ScapyImportError(e)

scapy.config.Conf.l2types.register_num2layer(119,
                                            scapy.layers.dot11.PrismHeader)


def isFlagSet(self, name, value):
    """Return True if the given field 'includes' the given value.
       Exact behaviour of this function is specific to the field-type.
    """
    field, val = self.getfield_and_val(name)
    if isinstance(field, scapy.fields.EnumField):
        if val not in field.i2s:
            return False
        return field.i2s[val] == value
    else:
        return (1 << field.names.index([value])) & self.__getattr__(name) != 0
scapy.packet.Packet.isFlagSet = isFlagSet
del isFlagSet


def areFlagsSet(self, name, values):
    """Return True if the given field 'includes' all of the given values."""
    return all(self.isFlagSet(name, value) for value in values)
scapy.packet.Packet.areFlagsSet = areFlagsSet
del areFlagsSet


def areFlagsNotSet(self, name, values):
    """Return True if the given field 'includes' none of the given values."""
    return all(not self.isFlagSet(name, value) for value in values)
scapy.packet.Packet.areFlagsNotSet = areFlagsNotSet
del areFlagsNotSet


def iterSubPackets(self, cls):
    """Iterate over all layers of the given type in packet 'self'."""
    if cls not in self:
        return
    elt = self[cls]
    while elt:
        yield elt
        elt = elt[cls:2]
scapy.packet.Packet.iterSubPackets = iterSubPackets
del iterSubPackets


class XStrFixedLenField(scapy.fields.StrFixedLenField):
    """String-Field with nice repr() for hexdecimal strings"""

    def i2repr(self, pkt, x):
        return util.str2hex(scapy.fields.StrFixedLenField.i2m(self, pkt, x))


class XStrLenField(scapy.fields.StrLenField):
    """String-Field of variable size with nice repr() for hexdecimal strings"""

    def i2repr(self, pkt, x):
        return util.str2hex(scapy.fields.StrLenField.i2m(self, pkt, x))


class EAPOL_Key(scapy.packet.Packet):
    """EAPOL Key frame"""
    name = "EAPOL Key"
    fields_desc = [scapy.fields.ByteEnumField("DescType", 254,
                                                {2: "RSN Key",
                                                254: "WPA Key"})]
scapy.packet.bind_layers(scapy.layers.l2.EAPOL, EAPOL_Key, type=3)


class EAPOL_AbstractEAPOLKey(scapy.packet.Packet):
    """Base-class for EAPOL WPA/RSN-Key frames"""
    fields_desc = [scapy.fields.FlagsField("KeyInfo", 0, 16,
                                ["HMAC_MD5_RC4", "HMAC_SHA1_AES", "undefined",\
                                 "pairwise", "idx1", "idx2", "install",\
                                 "ack", "mic", "secure", "error", "request", \
                                 "encrypted"]),
        scapy.fields.ShortField("KeyLength", 0),
        scapy.fields.LongField("ReplayCounter", 0),
        XStrFixedLenField("Nonce", '\x00'*32, 32),
        XStrFixedLenField("KeyIV", '\x00'*16, 16),
        XStrFixedLenField("WPAKeyRSC", '\x00'*8, 8),
        XStrFixedLenField("WPAKeyID", '\x00'*8, 8),
        XStrFixedLenField("WPAKeyMIC", '\x00'*16, 16),
        scapy.fields.ShortField("WPAKeyLength", 0),
        scapy.fields.ConditionalField(
                            XStrLenField("WPAKey", None,
                                length_from = lambda pkt: pkt.WPAKeyLength),\
                            lambda pkt: pkt.WPAKeyLength > 0)]


class EAPOL_WPAKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL WPA Key"
    keyscheme = 'HMAC_MD5_RC4'
scapy.packet.bind_layers(EAPOL_Key, EAPOL_WPAKey, DescType=254)


class EAPOL_RSNKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL RSN Key"
    keyscheme = 'HMAC_SHA1_AES'
scapy.packet.bind_layers(EAPOL_Key, EAPOL_RSNKey, DescType=2)


class AccessPoint(object):

    def __init__(self, mac):
        self.mac = mac
        self.essidframe = None
        self.essid = None
        self.stations = {}

    def __iter__(self):
        return self.stations.values().__iter__()

    def __str__(self):
        return self.mac

    def __contains__(self, mac):
        return mac in self.stations

    def __getitem__(self, mac):
        return self.stations[mac]

    def __setitem__(self, mac, station):
        self.stations[mac] = station

    def __len__(self):
        return len(self.stations)

    def getCompletedAuthentications(self):
        """Iterate over all Stations handled by this instance and return
           completed instances of Authentication.
        """
        for station in self.stations.itervalues():
            for auth in station:
                if auth.isCompleted():
                    yield auth

    def isCompleted(self):
        """Returns True if this instance includes at least one valid
           authentication.
        """
        return any(station.isCompleted() for station in self)


class Station(object):

    def __init__(self, mac, ap):
        self.ap = ap
        self.mac = mac
        self.auths = []

    def __str__(self):
        return self.mac

    def __iter__(self):
        return list(self.auths).__iter__()

    def __len__(self):
        return len(self.auths)

    def isCompleted(self):
        """Returns True if this instance includes at least one valid
           authentication.
        """
        return any(auth.isCompleted() for auth in self)


class EAPOLAuthentication(object):

    def __init__(self, station):
        self.station = station
        self.version = None
        self.snonce = None
        self.anonce = None
        self.keymic = None
        self.keymic_frame = None
        self.frames = dict.fromkeys(range(3))

    def isCompleted(self):
        """Returns True if all bits and parts required to attack this instance
           are set.
        """
        return all((self.version, self.snonce, self.anonce, self.keymic,
                    self.keymic_frame))

    def getpke(self):
        if not self.isCompleted():
            raise RuntimeError("Authentication not completed...")
        pke = "Pairwise key expansion\x00" \
               + ''.join(sorted((scapy.utils.mac2str(self.station.ap.mac), \
                                 scapy.utils.mac2str(self.station.mac)))) \
               + ''.join(sorted((self.snonce, self.anonce))) \
               + '\x00'
        return pke
    pke = property(getpke)


class EAPOLCrackerThread(threading.Thread, _cpyrit_cpu.EAPOLCracker):

    def __init__(self, workqueue, auth):
        threading.Thread.__init__(self)
        _cpyrit_cpu.EAPOLCracker.__init__(self, auth.version, auth.pke,
                                            auth.keymic, auth.keymic_frame)
        self.workqueue = workqueue
        self.solution = None
        self.setDaemon(True)
        self.start()

    def run(self):
        while True:
            solution = self.solve(self.workqueue.get())
            if solution:
                self.solution = solution
            self.workqueue.task_done()


class EAPOLCracker(object):

    def __init__(self, authentication):
        self.queue = Queue.Queue(10)
        self.workers = []
        self.solution = None
        for i in xrange(util.ncpus):
            self.workers.append(EAPOLCrackerThread(self.queue, authentication))

    def _getSolution(self):
        if self.solution is None:
            for worker in self.workers:
                if worker.solution is not None:
                    self.solution = worker.solution
                    break

    def enqueue(self, results):
        self.queue.put(results)
        self._getSolution()

    def join(self):
        self.queue.join()
        self._getSolution()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.join()


class Dot11PacketWriter(object):

    def __init__(self, pcapfile):
        self.writer = scapy.utils.PcapWriter(pcapfile, linktype=105,
                                        gz=pcapfile.endswith('.gz'), sync=True)
        self.pcktcount = 0

    def write(self, pckt):
        if not scapy.layers.dot11.Dot11 in pckt:
            raise RuntimeError("No Dot11-frame in packet.")
        self.writer.write(pckt[scapy.layers.dot11.Dot11])
        self.pcktcount += 1

    def close(self):
        self.writer.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()


class PacketParser(object):

    def __init__(self, pcapfile=None, new_ap_callback=None,
                new_station_callback=None, new_auth_callback=None):
        self.air = {}
        self.pcktcount = 0
        self.dot11_pcktcount = 0
        self.new_ap_callback = new_ap_callback
        self.new_station_callback = new_station_callback
        self.new_auth_callback = new_auth_callback
        if pcapfile is not None:
            self.parse_file(pcapfile)

    def _find_ssid(self, pckt):
        for elt_pckt in pckt.iterSubPackets(scapy.layers.dot11.Dot11Elt):
            if elt_pckt.isFlagSet('ID', 'SSID') \
             and not all(c == '\x00' for c in elt_pckt.info):
                return elt_pckt.info

    def _add_ap(self, ap_mac, pckt):
        ap = self.air.setdefault(ap_mac, AccessPoint(ap_mac))
        if ap.essid is None:
            essid = self._find_ssid(pckt)
            if essid is not None:
                ap.essid = essid
                ap.essidframe = pckt.copy()
                if self.new_ap_callback is not None:
                    self.new_ap_callback(ap)

    def _add_station(self, ap, sta_mac):
        if sta_mac not in ap:
            sta = Station(sta_mac, ap)
            ap[sta_mac] = sta
            if self.new_station_callback is not None:
                self.new_station_callback(sta)

    def parse_file(self, pcapfile):
        for pckt in scapy.utils.PcapReader(pcapfile):
            self.pcktcount += 1
            self.parse_packet(pckt)

    def parse_packet(self, pckt):
        if not scapy.layers.dot11.Dot11 in pckt:
            return
        dot11_pckt = pckt[scapy.layers.dot11.Dot11]
        self.dot11_pcktcount += 1

        if dot11_pckt.isFlagSet('type', 'Control'):
            return

        # Get a AP and a ESSID from a Beacon
        if scapy.layers.dot11.Dot11Beacon in dot11_pckt:
            self._add_ap(dot11_pckt.addr2, dot11_pckt)
            return

        # Get a AP and it's ESSID from a AssociationRequest
        if scapy.layers.dot11.Dot11AssoReq in dot11_pckt:
            self._add_ap(dot11_pckt.addr1, dot11_pckt)

        # From now on we are only interested in targeted packets
        if dot11_pckt.isFlagSet('FCfield', 'to-DS') \
         and dot11_pckt.addr2 != 'ff:ff:ff:ff:ff:ff':
            ap_mac = dot11_pckt.addr1
            sta_mac = dot11_pckt.addr2
        elif dot11_pckt.isFlagSet('FCfield', 'from-DS') \
         and dot11_pckt.addr1 != 'ff:ff:ff:ff:ff:ff':
            ap_mac = dot11_pckt.addr2
            sta_mac = dot11_pckt.addr1
        else:
            return

        # May result in 'anonymous' AP
        self._add_ap(ap_mac, dot11_pckt)
        ap = self.air[ap_mac]

        self._add_station(ap, sta_mac)
        sta = ap[sta_mac]

        if EAPOL_WPAKey in dot11_pckt:
            wpakey_pckt = dot11_pckt[EAPOL_WPAKey]
        elif EAPOL_RSNKey in dot11_pckt:
            wpakey_pckt = dot11_pckt[EAPOL_RSNKey]
        else:
            return

        # TODO For now we guess that there is only one consecutive,
        # non-overlapping authentication between ap and sta. We need a better
        # way to deal with multiple authentications than that...
        if len(sta.auths) > 0:
            auth = sta.auths[0]
        else:
            auth = EAPOLAuthentication(sta)
            sta.auths.append(auth)

        if auth.version is None:
            # WPAKeys 'should' set HMAC_MD5_RC4, RSNKeys HMAC_SHA1_AES
            # However we've seen cases where a WPAKey-packet sets
            # HMAC_SHA1_AES in it's KeyInfo-field (see issue #111)
            if wpakey_pckt.isFlagSet('KeyInfo', EAPOL_WPAKey.keyscheme):
                auth.version = EAPOL_WPAKey.keyscheme
            elif wpakey_pckt.isFlagSet('KeyInfo', EAPOL_RSNKey.keyscheme):
                auth.version = EAPOL_RSNKey.keyscheme
            else:
                # Fallback to default, in case the KeyScheme is never set
                # Should not happen...
                auth.version = wpakey_pckt.keyscheme

        # Frame 1: pairwise set, install unset, ack set, mic unset
        # results in ANonce
        if wpakey_pckt.areFlagsSet('KeyInfo', ('pairwise', 'ack')) \
         and wpakey_pckt.areFlagsNotSet('KeyInfo', ('install', 'mic')):
            auth.anonce = wpakey_pckt.Nonce
            auth.frames[0] = pckt.copy()
            if self.new_auth_callback is not None and auth.isCompleted():
                self.new_auth_callback(auth)

        # Frame 2: pairwise set, install unset, ack unset, mic set,
        # WPAKeyLength > 0 results in MIC and keymic_frame
        elif wpakey_pckt.areFlagsSet('KeyInfo', ('pairwise', 'mic')) \
         and wpakey_pckt.areFlagsNotSet('KeyInfo', ('install', 'ack')) \
         and wpakey_pckt.WPAKeyLength > 0:
            auth.keymic = wpakey_pckt.WPAKeyMIC
            auth.snonce = wpakey_pckt.Nonce
            auth.frames[1] = pckt.copy()
            # We need a revirginized version of the EAPOL-frame which produced
            # that MIC.
            frame = dot11_pckt[scapy.layers.dot11.EAPOL].copy()
            frame.WPAKeyMIC = '\x00'* len(frame.WPAKeyMIC)
            # Strip padding and cruft
            auth.keymic_frame = str(frame)[:frame.len + 4]
            if self.new_auth_callback is not None and auth.isCompleted():
                self.new_auth_callback(auth)

        # Frame 3: pairwise set, install set, ack set, mic set
        # Results in ANonce
        elif wpakey_pckt.areFlagsSet('KeyInfo', \
                                     ('pairwise', 'install', 'ack', 'mic')):
            auth.anonce = wpakey_pckt.Nonce
            auth.frames[2] = pckt.copy()
            if self.new_auth_callback is not None and auth.isCompleted():
                self.new_auth_callback(auth)

    def __iter__(self):
        return [ap for essid, ap in sorted([(ap.essid, ap) \
                               for ap in self.air.itervalues()])].__iter__()

    def __getitem__(self, bssid):
        return self.air[bssid]

    def __contains__(self, bssid):
        return bssid in self.air

    def __len__(self):
        return len(self.air)
