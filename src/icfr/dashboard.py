"""Local real-time network traffic forensics dashboard (IPv4)."""
from __future__ import annotations
import argparse, json, mimetypes, struct, threading, time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent / "web"

class Engine:
    def __init__(self, limit=2500):
        self.lock=threading.RLock(); self.events=deque(maxlen=limit); self.proto=Counter(); self.talkers=Counter(); self.bytes=Counter(); self.alerts=deque(maxlen=300)
        self.started=time.time(); self.total_packets=0; self.total_bytes=0; self.last_id=0; self.running=False; self.mode="idle"; self.source=""; self.dropped=0
        self.icmp_rates=defaultdict(deque); self.syn_ports=defaultdict(lambda:defaultdict(deque)); self.icfr=defaultdict(dict)
    @staticmethod
    def decode(frame, raw, timestamp=None):
        if len(raw)<20 or raw[0]>>4!=4: return None
        ihl=(raw[0]&15)*4
        if ihl<20 or len(raw)<ihl: return None
        plen=struct.unpack_from("!H",raw,2)[0]
        if plen<ihl or len(raw)<ihl: return None
        end=min(plen,len(raw)); proto=raw[9]; src=".".join(map(str,raw[12:16])); dst=".".join(map(str,raw[16:20]))
        names={1:"ICMP",6:"TCP",17:"UDP"}; name=names.get(proto,"OTHER"); sport=dport=None; flags=""; info=""
        off=ihl
        frag=struct.unpack_from("!H",raw,6)[0]
        if frag&0x1fff: return {"frame":frame,"timestamp":timestamp or time.time(),"src":src,"dst":dst,"protocol":name,"length":end,"sport":None,"dport":None,"flags":"","info":"IPv4 fragment (non-initial)","payload_preview":""}
        if proto==6 and end>=off+20:
            sport,dport=struct.unpack_from("!HH",raw,off); thl=(raw[off+12]>>4)*4
            f=raw[off+13]; flags="".join(k for bit,k in [(0x02,"S"),(0x10,"A"),(0x01,"F"),(0x04,"R"),(0x08,"P"),(0x20,"U")] if f&bit)
            info=f"{sport} → {dport} [{flags}]"; off+=max(20,thl)
        elif proto==17 and end>=off+8:
            sport,dport=struct.unpack_from("!HH",raw,off); info=f"{sport} → {dport}"; off+=8
        elif proto==1 and end>=off+8:
            typ,code=raw[off],raw[off+1]; info={0:"Echo reply",8:"Echo request",3:"Destination unreachable",11:"Time exceeded"}.get(typ,f"Type {typ} Code {code}")
            if typ in (0,8): info+=f" id={struct.unpack_from('!H',raw,off+4)[0]} seq={struct.unpack_from('!H',raw,off+6)[0]}"
            off+=8
        preview=raw[off:min(end,off+24)].hex(" ")
        return {"frame":frame,"timestamp":timestamp or time.time(),"src":src,"dst":dst,"protocol":name,"length":end,"sport":sport,"dport":dport,"flags":flags,"info":info,"payload_preview":preview}
    def alert(self, level, title, detail, event):
        self.alerts.appendleft({"time":event["timestamp"],"level":level,"title":title,"detail":detail,"frame":event["frame"],"src":event["src"],"dst":event["dst"]})
    def ingest(self, frame, raw, timestamp=None):
        event=self.decode(frame,raw,timestamp)
        if not event: return
        with self.lock:
            event["observed_at"]=time.time()
            self.last_id+=1; event["id"]=self.last_id; self.events.appendleft(event); self.total_packets+=1; self.total_bytes+=event["length"]
            self.proto[event["protocol"]]+=1; self.talkers[event["src"]]+=1; self.bytes[event["src"]]+=event["length"]
            now=event["timestamp"]
            if event["protocol"]=="ICMP":
                q=self.icmp_rates[event["src"]]; q.append(now)
                while q and now-q[0]>5: q.popleft()
                if len(q)>=30 and (len(q)==30 or len(q)%25==0): self.alert("high","ICMP rate threshold",f"{len(q)} ICMP packets from {event['src']} in 5 seconds; heuristic threshold is 30.",event)
                # ICFR metadata visibility without claiming payload reconstruction.
                off=(raw[0]&15)*4+8
                if len(raw)>=off+16 and raw[off:off+4]==b"ICFR":
                    fid,idx,total=struct.unpack_from("!III",raw,off+4); key=(event["src"],event["dst"],fid,total); rec=self.icfr[key]
                    if idx in rec and rec[idx][0]!=raw[off+16:min(len(raw),struct.unpack_from('!H',raw,2)[0])]: self.alert("high","ICFR chunk conflict",f"File ID {fid}, index {idx} appears with different payloads.",event)
                    elif idx in rec: self.alert("info","ICFR duplicate chunk",f"File ID {fid}, index {idx} repeated.",event)
                    else: rec[idx]=(raw[off+16:min(len(raw),struct.unpack_from('!H',raw,2)[0])],event["frame"])
                    event["icfr"]={"file_id":fid,"index":idx,"total":total,"observed":len(rec)}
            if event["protocol"]=="TCP" and "S" in event["flags"] and "A" not in event["flags"] and event["dport"] is not None:
                q=self.syn_ports[event["src"]][event["dport"]]; q.append(now)
                while q and now-q[0]>10: q.popleft()
                ports=self.syn_ports[event["src"]]
                for port,ts in list(ports.items()):
                    while ts and now-ts[0]>10: ts.popleft()
                    if not ts: ports.pop(port,None)
                if len(ports)>=20 and len(ports)%10==0:self.alert("medium","Possible SYN scan",f"{event['src']} sent SYN packets to {len(ports)} distinct ports in 10 seconds; heuristic only.",event)
    def snapshot(self):
        with self.lock:
            now=time.time(); buckets=[0]*30
            for e in self.events:
                age=now-e.get("observed_at",e["timestamp"])
                if 0<=age<30: buckets[29-int(age)]+=1
            return {"running":self.running,"mode":self.mode,"source":self.source,"dropped":self.dropped,"uptime":round(now-self.started,1),"total_packets":self.total_packets,"total_bytes":self.total_bytes,"protocols":dict(self.proto),"top_talkers":[{"ip":ip,"packets":n,"bytes":self.bytes[ip]} for ip,n in self.talkers.most_common(8)],"timeline":buckets,"events":list(self.events)[:300],"alerts":list(self.alerts)[:100],"updated":now}

def pcap_records(path):
    with Path(path).open("rb") as f:
        gh=f.read(24)
        fm={b"\xd4\xc3\xb2\xa1":"<",b"\xa1\xb2\xc3\xd4":">",b"\x4d\x3c\xb2\xa1":"<",b"\xa1\xb2\x3c\x4d":">"}
        if len(gh)!=24 or gh[:4] not in fm: raise ValueError("Classic PCAP required (PCAPNG unsupported)")
        end=fm[gh[:4]]; link=struct.unpack_from(end+"I",gh,20)[0]
        if link not in (1,101,113): raise ValueError(f"Unsupported PCAP link type: {link}")
        frame=0
        while True:
            h=f.read(16)
            if not h: break
            if len(h)!=16: raise ValueError("Truncated pcap record header")
            sec,frac,caplen,_=struct.unpack(end+"IIII",h); b=f.read(caplen)
            if len(b)!=caplen: raise ValueError("Truncated pcap record")
            frame+=1
            if link==1:
                if len(b)<14: continue
                et=struct.unpack_from("!H",b,12)[0]; off=14
                if et==0x8100 and len(b)>=18: et=struct.unpack_from("!H",b,16)[0]; off=18
                if et!=0x0800: continue
                raw=b[off:]
            elif link==113:
                if len(b)<16 or b[14:16]!=b"\x08\x00":continue
                raw=b[16:]
            else: raw=b
            yield frame,raw,sec+frac/(1e9 if gh[:4] in (b"\x4d\x3c\xb2\xa1",b"\xa1\xb2\x3c\x4d") else 1e6)

class Service:
    def __init__(self): self.engine=Engine(); self.stop=threading.Event(); self.worker=None; self.sniffer=None
    def stop_capture(self):
        self.stop.set()
        if self.sniffer is not None:
            try: self.sniffer.stop(join=False)
            except Exception: pass
        self.engine.running=False
    def replay(self,path,speed=1.0):
        self.stop.clear(); self.engine.running=True; self.engine.mode="PCAP replay"; self.engine.source=str(Path(path).resolve())
        def run():
            prev=None
            try:
                for n,raw,ts in pcap_records(path):
                    if self.stop.is_set():break
                    if speed>0 and prev is not None: self.stop.wait(min(max((ts-prev)/speed,0),2.0))
                    self.engine.ingest(n,raw,ts); prev=ts
            except Exception as ex: self.engine.alerts.appendleft({"time":time.time(),"level":"high","title":"PCAP replay error","detail":str(ex),"frame":0,"src":"","dst":""})
            self.engine.running=False
        self.worker=threading.Thread(target=run,daemon=True); self.worker.start()
    def live(self,interface,filter_expr):
        try: from scapy.all import IP, AsyncSniffer
        except ImportError: raise RuntimeError("Live capture requires Scapy: python -m pip install scapy")
        self.stop.clear(); self.engine.running=True; self.engine.mode="Live capture"; self.engine.source=interface or "default interface"
        def run():
            try:
                n=0
                def cb(pkt):
                    nonlocal n
                    if IP in pkt:
                        n+=1; self.engine.ingest(n,bytes(pkt[IP]),float(pkt.time))
                self.sniffer=AsyncSniffer(iface=interface or None,filter=filter_expr or "ip",prn=cb,store=False)
                self.sniffer.start(); self.sniffer.join()
            except Exception as ex: self.engine.alerts.appendleft({"time":time.time(),"level":"high","title":"Capture error","detail":str(ex),"frame":0,"src":"","dst":""})
            self.engine.running=False
        self.worker=threading.Thread(target=run,daemon=True); self.worker.start()

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("--host",default="127.0.0.1"); p.add_argument("--port",type=int,default=8765); p.add_argument("--pcap",type=Path); p.add_argument("--speed",type=float,default=1.0); p.add_argument("--live",action="store_true"); p.add_argument("--interface"); p.add_argument("--filter",default="ip"); a=p.parse_args()
    if a.live and a.pcap: p.error("choose either --live or --pcap")
    service=Service()
    if a.pcap: service.replay(a.pcap,a.speed)
    if a.live: service.live(a.interface,a.filter)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            path=urlparse(self.path).path
            if path=="/api/state": data=json.dumps(service.engine.snapshot()).encode(); ctype="application/json"
            elif path=="/api/export": data=json.dumps(service.engine.snapshot(),indent=2).encode(); ctype="application/json"
            else:
                name="index.html" if path=="/" else path.lstrip("/"); target=(ROOT/name).resolve()
                if ROOT.resolve() not in target.parents and target!=ROOT.resolve(): self.send_error(403); return
                if not target.is_file(): self.send_error(404); return
                data=target.read_bytes(); ctype=mimetypes.guess_type(target)[0] or "application/octet-stream"
            self.send_response(200); self.send_header("Content-Type",ctype+ ("; charset=utf-8" if ctype.startswith("text/") or "javascript" in ctype else "")); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
        def do_POST(self):
            if self.path=="/api/stop": service.stop_capture(); self.send_response(204); self.end_headers()
            else:self.send_error(404)
    server=ThreadingHTTPServer((a.host,a.port),Handler); print(f"Dashboard: http://{a.host}:{a.port}  mode={service.engine.mode or 'idle'}");
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: service.stop_capture(); server.server_close()
if __name__=="__main__":main()
