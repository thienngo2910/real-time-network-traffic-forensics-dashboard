import argparse
from pathlib import Path
from .core import analyze
from .pcapgen import build_dataset

def main():
 p=argparse.ArgumentParser(prog="icfr"); sub=p.add_subparsers(dest="cmd",required=True)
 a=sub.add_parser("analyze"); a.add_argument("pcap",type=Path); a.add_argument("-o","--output",type=Path,default=Path("results/run"))
 d=sub.add_parser("dataset"); d.add_argument("directory",type=Path)
 x=p.parse_args()
 if x.cmd=="analyze":
  r=analyze(x.pcap,x.output); print(f"Transfers: {r['recognized_transfers']}; report: {x.output/'report.json'}")
 else: build_dataset(x.directory); print(f"Generated dataset: {x.directory}")
if __name__=="__main__": main()
