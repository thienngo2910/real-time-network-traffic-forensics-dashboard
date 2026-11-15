"""Dependency-free deterministic PCAP fixture generator."""
import struct, random, hashlib
from pathlib import Path
from .core import HEADER, MAGIC

def checksum(data):
    if len(data)%2: data+=b"\0"
    s=sum(struct.unpack("!%dH"%(len(data)//2),data))
    while s>>16: s=(s&0xffff)+(s>>16)
    return (~s)&0xffff

def packet(src,dst,payload,ident=1,seq=1):
    icmp=struct.pack("!BBHHH",8,0,0,ident,seq)+payload
    icmp=icmp[:2]+struct.pack("!H",checksum(icmp))+icmp[4:]
    s=bytes(map(int,src.split("."))); d=bytes(map(int,dst.split(".")))
    ip=struct.pack("!BBHHHBBH4s4s",0x45,0,len(icmp)+20,ident,0,64,1,0,s,d)
    ip=ip[:10]+struct.pack("!H",checksum(ip))+ip[12:]
    eth=bytes.fromhex("0200000000020200000000010800")
    return eth+ip+icmp

def write_pcap(path, packets):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1))
        for i,p in enumerate(packets):
            f.write(struct.pack("<IIII",1700000000+i,0,len(p),len(p))); f.write(p)

def build_dataset(root):
    data=(b"Network forensics ICMP reconstruction demonstration.\n"+
          bytes(range(256))*3+b"\nEnd of binary sample.\x00\xff")
    src,dst,fid="192.168.201.130","192.168.201.1",0x1CF0
    size=128
    chunks=[data[i:i+size] for i in range(0,len(data),size)]
    encoded=[HEADER.pack(MAGIC,fid,i,len(chunks))+c for i,c in enumerate(chunks)]
    icfr=[packet(src,dst,p,i+1,i+1) for i,p in enumerate(encoded)]
    noise=[packet(src,dst,b"ordinary ping payload "+bytes([i]),90+i,1) for i in range(3)]
    duplicate=icfr[1]
    conflict=packet(src,dst,HEADER.pack(MAGIC,fid,1,len(chunks))+b"CONFLICT"+chunks[1][8:],77,1)
    scenarios={
      "complete":icfr,
      "noise":noise+icfr,
      "reordered":list(reversed(icfr)),
      "duplicate":icfr+[duplicate],
      "missing":icfr[:2]+icfr[3:],
      "conflict":icfr+[conflict],
      "combined":noise+[icfr[i] for i in [3,0,1,1,4,2,5]][:-1]+[conflict],
    }
    for name,ps in scenarios.items(): write_pcap(root/f"{name}.pcap",ps)
    (root/"ground_truth.json").write_text(__import__("json").dumps({
      "source_file":"synthetic deterministic binary payload","bytes":len(data),
      "sha256":hashlib.sha256(data).hexdigest(),"chunk_size":size,"chunk_count":len(chunks),
      "scope":"synthetic; not captured from a live network"
    },indent=2),encoding="utf-8")
