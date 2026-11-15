from __future__ import annotations
import hashlib, json, struct
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

MAGIC = b"ICFR"
HEADER = struct.Struct("!4sIII")  # magic, file_id, zero-based index, total

@dataclass
class Chunk:
    frame: int
    src: str
    dst: str
    file_id: int
    index: int
    total: int
    data: bytes

def parse_icmp_frame(frame_no: int, packet: bytes):
    """Return ICFR tuple for IPv4 ICMP echo request/reply, else None."""
    if len(packet) < 20 or packet[0] >> 4 != 4: return None
    ihl = (packet[0] & 15) * 4
    if ihl < 20 or len(packet) < ihl + 8: return None
    total_len = struct.unpack_from("!H", packet, 2)[0]
    if total_len < ihl + 8: return None
    # Fragmented IPv4 payloads are deliberately out of scope.
    frag = struct.unpack_from("!H", packet, 6)[0]
    if frag & 0x3fff: return None
    if packet[9] != 1: return None
    icmp = packet[ihl:min(total_len, len(packet))]
    if len(icmp) < 8 or icmp[0] not in (0, 8): return None
    payload = icmp[8:]
    if len(payload) < HEADER.size or payload[:4] != MAGIC: return None
    _, fid, index, total = HEADER.unpack_from(payload)
    data = payload[HEADER.size:]
    if total == 0 or total > 1_000_000 or index >= total: return None
    return Chunk(frame_no, ".".join(map(str, packet[12:16])), ".".join(map(str, packet[16:20])), fid,index,total,data)

def read_pcap(path: Path):
    """Small classic-PCAP reader for Ethernet, raw IPv4, and Linux cooked v1."""
    with path.open("rb") as f:
        gh=f.read(24)
        if len(gh)!=24: raise ValueError("Truncated PCAP global header")
        magic=gh[:4]
        formats={b"\xd4\xc3\xb2\xa1":("<","us"), b"\xa1\xb2\xc3\xd4":(">","us"),
                 b"\x4d\x3c\xb2\xa1":("<","ns"), b"\xa1\xb2\x3c\x4d":(">","ns")}
        if magic not in formats: raise ValueError("Unsupported PCAP magic (classic PCAP required)")
        endian,_=formats[magic]
        linktype=struct.unpack_from(endian+"I",gh,20)[0]
        if linktype not in (1,101,113): raise ValueError(f"Unsupported link type {linktype}")
        frame=0
        while True:
            rh=f.read(16)
            if not rh: break
            if len(rh)!=16: raise ValueError("Truncated PCAP packet header")
            _,_,incl,_=struct.unpack(endian+"IIII",rh)
            raw=f.read(incl)
            if len(raw)!=incl: raise ValueError("Truncated PCAP packet data")
            frame+=1
            if linktype==1:
                if len(raw)<14 or raw[12:14]!=b"\x08\x00": continue
                ip=raw[14:]
            elif linktype==113:
                if len(raw)<16 or raw[14:16]!=b"\x08\x00": continue
                ip=raw[16:]
            else: ip=raw
            yield frame,ip

def analyze(pcap: Path, outdir: Path):
    groups=defaultdict(list)
    rejected=0
    for frame,ip in read_pcap(pcap):
        c=parse_icmp_frame(frame,ip)
        if c: groups[(c.src,c.dst,c.file_id,c.total)].append(c)
        else: rejected+=1
    outdir.mkdir(parents=True,exist_ok=True)
    reports=[]
    for (src,dst,fid,total),chunks in sorted(groups.items()):
        byidx=defaultdict(list)
        for c in chunks: byidx[c.index].append(c)
        conflicts={i for i,cs in byidx.items() if len({c.data for c in cs})>1}
        missing=sorted(set(range(total))-set(byidx))
        selected={i:cs[0] for i,cs in byidx.items() if i not in conflicts}
        assembled=b"".join(selected[i].data for i in range(total) if i in selected)
        complete=not missing and not conflicts
        name=f"recovered_{src.replace('.','-')}_{dst.replace('.','-')}_{fid}.bin"
        if assembled: (outdir/name).write_bytes(assembled)
        reports.append({
            "source":src,"destination":dst,"file_id":fid,"total_chunks":total,
            "observed_frames":len(chunks),"observed_chunk_indexes":sorted(byidx),
            "missing_indexes":missing,
            "duplicate_indexes":sorted(i for i,cs in byidx.items() if len(cs)>1 and i not in conflicts),
            "conflicting_indexes":sorted(conflicts),
            "chunk_frames":{str(i):[c.frame for c in cs] for i,cs in sorted(byidx.items())},
            "conflict_frames":{str(i):[c.frame for c in byidx[i]] for i in sorted(conflicts)},
            "complete":complete,"output_file":name if assembled else None,
            "bytes_reconstructed":len(assembled),"sha256":hashlib.sha256(assembled).hexdigest(),
            "note":"SHA-256 is comparable only when the expected source hash is independently known."
        })
    report={"pcap":str(pcap),"recognized_transfers":len(reports),"ignored_or_non_icfr_ipv4_frames":rejected,"transfers":reports}
    (outdir/"report.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    return report

def sequential_baseline(chunks):
    """Naive capture-order concatenation of all recognized chunk bodies."""
    return b"".join(c.data for c in chunks)
