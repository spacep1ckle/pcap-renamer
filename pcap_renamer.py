#!/usr/bin/env python3


import sys
import os
import re
from collections import Counter
from scapy.all import RawPcapReader, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, conf

# reduce scapy verbosity
conf.verb = 0

ILLEGAL_CHARS = re.compile(r'[\x00-\x1f<>:"/\\|?*\u2028\u2029]')

def sanitize_filename(s, max_len=120):
    if s is None:
        return None
    s = str(s).strip()
    s = ILLEGAL_CHARS.sub(' ', s)
    s = re.sub(r'\s+', ' ', s).strip()
    if len(s) == 0:
        return None
    return s[:max_len]

def extract_ssids_from_pcap(path, max_packets=None):
    ssids = []
    try:
        for i, (pkt_data, pkt_meta) in enumerate(RawPcapReader(path)):
            if max_packets and i >= max_packets:
                break
            # try to parse 802.11 frame
            try:
                pkt = Dot11(pkt_data)
            except Exception:
                # not an 802.11 frame
                continue
            # management frames only (type 0)
            if pkt.type != 0:
                continue
            subtype = pkt.subtype
            # Beacon (8), Probe Request (4), Probe Response (5)
            if subtype not in (4, 5, 8):
                continue
            # SSID element is in the 802.11 information elements; Scapy exposes them in
            # Dot11Elt layers; find Dot11Elt with ID 0
            elt = pkt.getlayer('Dot11Elt')
            while elt:
                if elt.ID == 0:
                    ssid = elt.info.decode(errors='ignore')
                    if ssid is not None:
                        ssid = ssid.strip()
                        if ssid != '':
                            ssids.append(ssid)
                    break
                elt = elt.payload.getlayer('Dot11Elt')
    except Exception as e:
        # RawPcapReader can raise on some formats like certain pcapng variants;
        # caller can decide how to handle
        raise
    return ssids

def choose_ssid(ssid_list):
    if not ssid_list:
        return None
    c = Counter(ssid_list)
    most, _ = c.most_common(1)[0]
    return most

def safe_unique_target(dirpath, base, ext):
    candidate = f"{base}{ext}"
    existing = set(os.listdir(dirpath))
    if candidate not in existing:
        return os.path.join(dirpath, candidate)
    i = 1
    while True:
        candidate = f"{base}_{i}{ext}"
        if candidate not in existing:
            return os.path.join(dirpath, candidate)
        i += 1

def process_dir(dirpath):
    for fname in os.listdir(dirpath):
        if not re.search(r'\.(pcap|pcapng|cap)$', fname, re.IGNORECASE):
            continue
        full = os.path.join(dirpath, fname)
        print(f"Processing: {fname}")
        try:
            ssids = extract_ssids_from_pcap(full)
        except Exception as e:
            print(f"  [ERROR] cannot parse {fname}: {e}")
            continue
        if not ssids:
            print("  [SKIP] no SSIDs found")
            continue
        chosen = choose_ssid(ssids)
        safe = sanitize_filename(chosen)
        if not safe:
            print("  [SKIP] SSID not usable as filename")
            continue
        base, ext = os.path.splitext(fname)
        # keep original extension
        target = safe_unique_target(dirpath, safe, ext)
        try:
            os.rename(full, target)
            print(f"  [RENAMED] -> {os.path.basename(target)}")
        except Exception as e:
            print(f"  [ERROR] could not rename: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap_renamer.py /path/to/pcap_dir")
        sys.exit(1)
    dirpath = sys.argv[1]
    if not os.path.isdir(dirpath):
        print("Not a directory:", dirpath)
        sys.exit(1)
    process_dir(dirpath)
    print("Done")

if __name__ == '__main__':
    main()