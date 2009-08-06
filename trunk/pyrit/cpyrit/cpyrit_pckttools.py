# -*- coding: UTF-8 -*-
#
#    Copyright 2008, 2009, Lukas Lueg, lukas.lueg@gmail.com
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

import threading
import Queue

import cpyrit_util as util
import _cpyrit_pckttools

try:
    import scapy.config
    import scapy.fields
    import scapy.layers.dot11
    import scapy.packet
    import scapy.utils
except ImportError, e:
    raise util.ScapyImportError(e)

scapy.config.Conf.l2types.register_num2layer(119, scapy.layers.dot11.PrismHeader)

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
    elt = self[cls]
    while elt:
        yield elt
        elt = elt[cls:2]
scapy.packet.Packet.iterSubPackets = iterSubPackets
del iterSubPackets

def hex2str(string):
    """Convert a binary string to hex-decimal representation."""
    return ''.join('%02x' % c for c in map(ord, string))


class XStrFixedLenField(scapy.fields.StrFixedLenField):
    """String-Field with nice repr() for hexdecimal strings"""
    def i2repr(self, pkt, x):
        return hex2str(StrFixedLenField.i2m(self, pkt, x))

class XStrLenField(scapy.fields.StrLenField):
    """String-Field of variables size with nice repr() for hexdecimal strings"""
    def i2repr(self, pkt, x):
        return hex2str(StrLenField.i2m(self, pkt, x))


class EAPOL_Key(scapy.packet.Packet):
    """EAPOL Key frame"""
    name = "EAPOL Key"
    fields_desc = [ scapy.fields.ByteEnumField("DescType", 254, {2: "RSN Key", 254: "WPA Key"}) ]
scapy.packet.bind_layers( scapy.layers.l2.EAPOL, EAPOL_Key, type=3 )


class EAPOL_AbstractEAPOLKey(scapy.packet.Packet):
    """Base-class for EAPOL WPA/RSN-Key frames"""
    fields_desc = [
        scapy.fields.FlagsField("KeyInfo", 0, 16,
                                ["HMAC_MD5_RC4", "HMAC_SHA1_AES", "undefined",\
                                 "pairwise", "idx1", "idx2", "install",\
                                 "ack", "mic", "secure", "error", "request", "encrypted"
                                ]),
        scapy.fields.ShortField("KeyLength", 0),
        scapy.fields.LongField("ReplayCounter", 0),
        XStrFixedLenField("Nonce", '\x00'*32, 32),
        XStrFixedLenField("KeyIV", '\x00'*16, 16),
        XStrFixedLenField("WPAKeyRSC", '\x00'*8, 8),
        XStrFixedLenField("WPAKeyID", '\x00'*8, 8),
        XStrFixedLenField("WPAKeyMIC", '\x00'*16, 16),
        scapy.fields.ShortField("WPAKeyLength", 0),
        scapy.fields.ConditionalField(
                        XStrLenField("WPAKey", None, length_from = lambda pkt: pkt.WPAKeyLength),\
                        lambda pkt: pkt.WPAKeyLength > 0 \
                        )
      ]


class EAPOL_WPAKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL WPA Key"
    keyscheme = 'HMAC_MD5_RC4'
scapy.packet.bind_layers( EAPOL_Key, EAPOL_WPAKey, DescType=254 )


class EAPOL_RSNKey(EAPOL_AbstractEAPOLKey):
    name = "EAPOL RSN Key"
    keyscheme = 'HMAC_SHA1_AES'
scapy.packet.bind_layers( EAPOL_Key, EAPOL_RSNKey, DescType=2   )


class AccessPoint(object):
    def __init__(self, bssid):
        self.bssid = bssid
        self.essid = None
        self.auths = {}

    def __iter__(self):
        return self.auths.keys().__iter__()
    
    def __str__(self):
        return self.bssid
    
    def __getitem__(self, sta):
        return self.auths[sta]
        
    def __len__(self):
        return len(self.getCompletedAuthentications())

    def iterStations(self):
        return self.__iter__()

    def iterAuthentications(self):
        return self.auths.values().__iter__()

    def getCompletedAuthentications(self):
        return [auth for auth in self.iterAuthentications() if auth.iscomplete()]
    
    def getpke(self, sta):
        auth = self.auths[sta]
        if not auth.iscomplete():
            raise RuntimeError, "Authentication not completed..."
        pke = "Pairwise key expansion\x00" \
               + ''.join(sorted((scapy.utils.mac2str(self.bssid), scapy.utils.mac2str(auth.sta)))) \
               + ''.join(sorted((auth.snonce, auth.anonce))) \
               + '\x00'
        return pke


class EAPOLAuthentication(object):
    def __init__(self, sta):
        self.sta = sta
        self.version = None
        self.snonce = None
        self.anonce = None
        self.keymic = None
        self.frame = None

    def iscomplete(self):
        return all((self.sta, self.version, self.snonce, self.anonce, self.keymic, self.frame))


class PacketParser(object):
    def __init__(self, pcapfile):
        self.air = {}
        self.pcktcount = 0
        self.dot11_pcktcount = 0
        for pckt in scapy.utils.PcapReader(pcapfile):
            self.pcktcount += 1
            if not scapy.layers.dot11.Dot11 in pckt:
                continue
                
            dot11_pckt = pckt[scapy.layers.dot11.Dot11]
            self.dot11_pcktcount += 1
            if dot11_pckt.isFlagSet('type', 'Control'):
                continue

            # Get a AP and a ESSID from a Beacon
            if scapy.layers.dot11.Dot11Beacon in dot11_pckt:
                ap = self.air.setdefault(dot11_pckt.addr2, AccessPoint(dot11_pckt.addr2))
                for elt_pckt in dot11_pckt[scapy.layers.dot11.Dot11Beacon].iterSubPackets(scapy.layers.dot11.Dot11Elt):
                    if elt_pckt.isFlagSet('ID','SSID'):
                        ap.essid = elt_pckt.info
                        break
                continue

            # Get a AP and it's ESSID from a AssociationRequest
            if scapy.layers.dot11.Dot11AssoReq in dot11_pckt:
                ap = self.air.setdefault(dot11_pckt.addr1, AccessPoint(dot11_pckt.addr1))
                for elt_pckt in dot11_pckt[scapy.layers.dot11.Dot11AssoReq].iterSubPackets(scapy.layers.dot11.Dot11Elt):
                    if elt_pckt.isFlagSet('ID', 'SSID'):
                        ap.essid = elt_pckt.info
                        break
                continue

            # Now we are only interested in targeted packets
            if dot11_pckt.isFlagSet('FCfield', 'to-DS'):
                ap = self.air.setdefault(dot11_pckt.addr1, AccessPoint(dot11_pckt.addr1))
                sta_mac = dot11_pckt.addr2
            elif dot11_pckt.isFlagSet('FCfield', 'from-DS'):
                ap = self.air.setdefault(dot11_pckt.addr2, AccessPoint(dot11_pckt.addr2))
                sta_mac = dot11_pckt.addr1
            else:
                continue
            
            if EAPOL_WPAKey in dot11_pckt:
                wpakey_pckt = dot11_pckt[EAPOL_WPAKey]
            elif EAPOL_RSNKey in dot11_pckt:
                wpakey_pckt = dot11_pckt[EAPOL_RSNKey]
            else:
                continue
            
            # WPAKey should be MD5/RC4, RSNKey should be SHA1/AES
            if not wpakey_pckt.isFlagSet('KeyInfo', wpakey_pckt.keyscheme):
                continue
            auth = ap.auths.setdefault(sta_mac, EAPOLAuthentication(sta_mac))
            auth.version = wpakey_pckt.keyscheme
                    
            # Frame 1: pairwise set, install unset, ack set, mic unset
            # results in ANonce
            if wpakey_pckt.areFlagsSet('KeyInfo', ('pairwise', 'ack')) \
             and wpakey_pckt.areFlagsNotSet('KeyInfo', ('install', 'mic')):
                auth.anonce = wpakey_pckt.Nonce
               
            # Frame 2: pairwise set, install unset, ack unset, mic set, WPAKeyLength > 0
            # results in MIC and eapolframe, frame 2 results in snonce
            elif wpakey_pckt.areFlagsSet('KeyInfo', ('pairwise', 'mic')) \
             and wpakey_pckt.areFlagsNotSet('KeyInfo', ('install', 'ack')) \
             and wpakey_pckt.WPAKeyLength > 0:
                auth.keymic = wpakey_pckt.WPAKeyMIC
                auth.snonce = wpakey_pckt.Nonce
                # We need a revirginized version of the whole EAPOL-frame.
                eapolframe = dot11_pckt[scapy.layers.dot11.EAPOL].copy()
                eapolframe.WPAKeyMIC = '\x00'* len(eapolframe.WPAKeyMIC)
                auth.frame = str(eapolframe)
                
            # Frame 3: pairwise set, install set, ack set, mic set
            # Results in ANonce
            elif wpakey_pckt.areFlagsSet('KeyInfo', ('pairwise', 'install', 'ack', 'mic')):
                auth.anonce = wpakey_pckt.Nonce

    def __iter__(self):
        return self.air.values().__iter__()

    def __getitem__(self, bssid):
        return self.air[bssid]

    def __contains__(self, bssid):
        return bssid in self.air

    def __len__(self):
        return len(self.air)


class EAPOLCrackerThread(threading.Thread, _cpyrit_pckttools.EAPOLCracker):
    def __init__(self, workqueue, keyscheme, pke, keymic, eapolframe):
        threading.Thread.__init__(self)
        _cpyrit_pckttools.EAPOLCracker.__init__(self, keyscheme, pke, keymic, eapolframe)
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
    def __init__(self, keyscheme, pke, keymic, eapolframe):
        self.queue = Queue.Queue(5)
        self.workers = []
        self.solution = None
        for i in xrange(util.ncpus):
            self.workers.append(EAPOLCrackerThread(self.queue, keyscheme, pke, keymic, eapolframe))

    def _getSolution(self):
        if not self.solution:
            finished_workers = filter(lambda w: w.solution, self.workers)
            if len(finished_workers) > 0:
                self.solution = finished_workers[0].solution
        
    def enqueue(self, results):
        self.queue.put(results)
        self._getSolution()

    def join(self):
        self.queue.join()
        self._getSolution()

