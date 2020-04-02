#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a message for WEP """

__author__      = "Nemanja Pantic et David Simeonovic"

from scapy.all import *
import binascii
from rc4 import RC4
import zlib
import struct

# Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

# Lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]  

# Données à envoyer
data = ['123456'*6, 'abcdef'*6, 'zoulou'*6]

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# Initialisation de RC4
cipher = RC4(seed, streaming=False)

# Liste contenant nos paquets
pktList = []

for i in range(3):
    pkt = arp.copy()
    # Génération du ICV
    pkt.SC = i
    icv = zlib.crc32(bytes(data[i], 'UTF-8'))
    icv = struct.pack("<L", icv)

    # Chiffrement avec RC4
    cipherText = cipher.crypt(bytes(data[i], 'UTF-8') + icv)

    # Remplacement des champs dans notre packet
    pkt.wepdata = cipherText[:-4]
    pkt.icv = struct.unpack("!L", cipherText[-4:])[0]

    if(i != 2):
        pkt.FCfield = 0x0845
    else:
        pkt.FCfield = 0x0841

    pktList.append(pkt)

# Génération du fichier pcap
wrpcap('fragment.pcap', pktList) 