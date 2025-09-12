from scapy.all import sniff
from . import config

def start_sniff(callback):
    sniff(iface=config.INTERFACE, prn=callback, store=False)
