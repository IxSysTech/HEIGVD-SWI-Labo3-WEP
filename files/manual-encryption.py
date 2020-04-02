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

# Changement des données dans la trame
data = '123456'*6

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# Génération du ICV
icv = zlib.crc32(bytes(data, 'UTF-8'))
icv = struct.pack("<L", icv)

# Chiffrement avec RC4
cipher = RC4(seed, streaming=False)
cipherText = cipher.crypt(bytes(data, 'UTF-8') + icv)

# Remplacement des champs dans notre packet
arp.wepdata = cipherText[:-4]
arp.icv = struct.unpack("!L", cipherText[-4:])[0]

# Génération du fichier pcap
wrpcap('encrypted.pcap', arp) 