#!/usr/bin/env python3
"""
gen_lst.py — Génère all.lst : tout l'internet IPv4 public, rien que le public.
Soustrait chirurgicalement les plages privées/réservées exactes (pas de /8 entiers).
Usage : python3 gen_lst.py
"""
import ipaddress, pathlib

# Plages privées/réservées EXACTES à retirer
PRIVATE = [
    "0.0.0.0/8",          # this network
    "10.0.0.0/8",         # RFC 1918
    "100.64.0.0/10",      # CGN / shared space
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local
    "172.16.0.0/12",      # RFC 1918 (172.16–172.31 seulement)
    "192.0.0.0/24",       # IETF protocol assignments
    "192.0.2.0/24",       # TEST-NET-1
    "192.88.99.0/24",     # 6to4 relay
    "192.168.0.0/16",     # RFC 1918
    "198.18.0.0/15",      # benchmark (198.18 + 198.19 seulement)
    "198.51.100.0/24",    # TEST-NET-2
    "203.0.113.0/24",     # TEST-NET-3
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # réservé futur
    "255.255.255.255/32", # broadcast
]

private_nets = [ipaddress.ip_network(p) for p in PRIVATE]

# Part de l'internet entier et soustrait précisément chaque plage privée
public = [ipaddress.ip_network("0.0.0.0/0")]
for priv in private_nets:
    new = []
    for net in public:
        if net.overlaps(priv):
            new.extend(net.address_exclude(priv))
        else:
            new.append(net)
    public = new

# Trie et collapse (fusionne les blocs adjacents)
public = list(ipaddress.collapse_addresses(public))
public.sort(key=lambda x: x.network_address)

total_ips = sum(n.num_addresses for n in public)
lines = "\n".join(str(n) for n in public)

out = pathlib.Path("all.lst")
out.write_text(lines + "\n")
print(f"[+] {len(public)} ranges CIDR écrits dans all.lst")
print(f"[+] {total_ips:,} adresses publiques (~{total_ips/2**32*100:.1f}% de l'IPv4)")
print(f"[+] Taille fichier : {out.stat().st_size // 1024} Ko")
