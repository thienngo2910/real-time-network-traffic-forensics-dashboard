"""Scapy ICFR sender; run only on a lab network you control."""
import argparse, hashlib, secrets, struct
from pathlib import Path
from .core import HEADER, MAGIC

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("file",type=Path); p.add_argument("--destination",required=True)
    p.add_argument("--chunk-size",type=int,default=512); p.add_argument("--file-id",type=lambda x:int(x,0),default=None)
    p.add_argument("--interval",type=float,default=.05); p.add_argument("--count-only",action="store_true")
    a=p.parse_args()
    if not 1<=a.chunk_size<=1400: p.error("chunk-size must be 1..1400 bytes")
    data=a.file.read_bytes(); fid=a.file_id if a.file_id is not None else secrets.randbits(32)
    chunks=[data[i:i+a.chunk_size] for i in range(0,len(data),a.chunk_size)] or [b""]
    print(f"file_id={fid} chunks={len(chunks)} bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
    if a.count_only: return
    try: from scapy.all import IP, ICMP, Raw, send
    except ImportError as e: raise SystemExit("Install Scapy first: python3 -m pip install scapy") from e
    for i,c in enumerate(chunks):
        send(IP(dst=a.destination)/ICMP(type=8,seq=i+1)/Raw(HEADER.pack(MAGIC,fid,i,len(chunks))+c),verbose=False)
        import time; time.sleep(a.interval)
if __name__=="__main__": main()
