import csv, hashlib, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from icfr.core import analyze, read_pcap, parse_icmp_frame, sequential_baseline
from icfr.pcapgen import build_dataset

def main():
 ds=ROOT/"datasets/generated"; build_dataset(ds)
 gt=json.loads((ds/"ground_truth.json").read_text()); expected=gt["sha256"]
 rows=[]
 for pcap in sorted(ds.glob("*.pcap")):
  if pcap.name=="ground_truth.json": continue
  out=ROOT/"results"/pcap.stem
  report=analyze(pcap,out); t=report["transfers"][0] if report["transfers"] else None
  chunks=[parse_icmp_frame(n,ip) for n,ip in read_pcap(pcap)]
  chunks=[c for c in chunks if c]
  baseline=sequential_baseline(chunks)
  rows.append({"scenario":pcap.stem,"frames":sum(1 for _ in read_pcap(pcap)),
    "robust_complete":bool(t and t["complete"]),"robust_sha256_match":bool(t and t["sha256"]==expected),
    "robust_missing":len(t["missing_indexes"]) if t else None,"robust_conflicts":len(t["conflicting_indexes"]) if t else None,
    "robust_duplicates":len(t["duplicate_indexes"]) if t else None,
    "baseline_sha256_match":hashlib.sha256(baseline).hexdigest()==expected,
    "baseline_bytes":len(baseline),"robust_bytes":t["bytes_reconstructed"] if t else 0})
 with (ROOT/"results"/"evaluation.csv").open("w",newline="",encoding="utf-8") as f:
  w=csv.DictWriter(f,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
 (ROOT/"results"/"evaluation.json").write_text(json.dumps({"ground_truth":gt,"results":rows},indent=2),encoding="utf-8")
 byname={r["scenario"]:r for r in rows}
 expected_checks={
  "complete":(True,True), "noise":(True,True), "reordered":(True,False),
  "duplicate":(True,False), "missing":(False,False), "conflict":(False,False),
  "combined":(False,False),
 }
 for name,(is_complete,baseline_match) in expected_checks.items():
  r=byname[name]
  assert (r["robust_complete"],r["robust_sha256_match"])==(is_complete,is_complete), (name,r)
  assert r["baseline_sha256_match"]==baseline_match, (name,r)
 assert byname["missing"]["robust_missing"]==1
 assert byname["conflict"]["robust_conflicts"]==1
 assert byname["duplicate"]["robust_duplicates"]==1
 (ROOT/"results"/"verification.txt").write_text(
  "PASS: 7 scenario expectations; source SHA-256 " + expected + "\n",encoding="utf-8")
 print("Scenario | robust complete | robust SHA-256 | baseline SHA-256 | missing | conflicts | duplicates")
 for r in rows: print(f"{r['scenario']} | {r['robust_complete']} | {r['robust_sha256_match']} | {r['baseline_sha256_match']} | {r['robust_missing']} | {r['robust_conflicts']} | {r['robust_duplicates']}")
if __name__=="__main__": main()
