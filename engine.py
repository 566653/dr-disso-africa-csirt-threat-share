"""Offline defensive risk triage; no external network calls."""
import argparse,hashlib,json,pathlib
RULES={"critical":("unauthorized","ransomware","exfiltration","tamper","compromised","disabled_backup"),"high":("suspicious","unexpected","privilege","failed_login","sim_swap","fraud","unpatched"),"medium":("review","outdated","unknown","configuration","warning")}
def assess(records):
    if not isinstance(records,list): raise ValueError("Expected a JSON list of events")
    findings=[]
    for index,item in enumerate(records):
        if not isinstance(item,dict): raise ValueError("Every event must be a JSON object")
        description=" ".join(str(item.get(k,"")) for k in ("event","detail","status")).lower()
        severity="info"
        for level,words in RULES.items():
            if any(word in description for word in words): severity=level;break
        findings.append({"index":index,"event_id":str(item.get("id",index)),"severity":severity,"reason":"Rule-based defensive review; analyst validation required"})
    return findings
def run(input_path):
    raw=pathlib.Path(input_path).read_bytes()
    findings=assess(json.loads(raw.decode("utf-8")))
    return {"project":pathlib.Path(__file__).parent.name,"schema_version":"1.0","input_sha256":hashlib.sha256(raw).hexdigest(),"count":len(findings),"findings":findings,"notice":"Demonstration triage only; analyst validation required."}
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("input");p.add_argument("--output");a=p.parse_args()
    result=json.dumps(run(a.input),indent=2,ensure_ascii=False)
    if a.output:pathlib.Path(a.output).write_text(result+"\n",encoding="utf-8")
    else:print(result)
