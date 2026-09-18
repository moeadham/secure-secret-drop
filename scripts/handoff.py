#!/usr/bin/env python3
"""One-time TLS-only secret handoff. Values are never displayed by this CLI."""
import argparse, html, http.client, http.server, json, os, re, secrets, shutil, signal, socket, ssl, subprocess, sys, tempfile, threading, time, urllib.error, urllib.parse, urllib.request
from pathlib import Path

MAX_BODY=32768; MAX_VALUE=8192; MAX_FIELDS=32; KEY_RE=re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
def default_root():
 override=os.environ.get("SECURE_SECRET_DROP_STATE_DIR")
 if override: return Path(override).expanduser()
 base=Path(os.environ["XDG_STATE_HOME"]).expanduser() if os.environ.get("XDG_STATE_HOME") else Path.home()/".local"/"state"
 return base/"secure-secret-drop"
ROOT=default_root()
def find_cloudflared():
 override=os.environ.get("CLOUDFLARED_BIN")
 if override: return str(Path(override).expanduser())
 found=shutil.which("cloudflared")
 if found: return found
 for candidate in ("/opt/homebrew/bin/cloudflared","/usr/local/bin/cloudflared","/usr/bin/cloudflared",str(Path.home()/".local/bin/cloudflared")):
  if Path(candidate).is_file() and os.access(candidate,os.X_OK): return candidate
 return "cloudflared"
CLOUDFLARED=find_cloudflared()
def resolved_cloudflared():
 candidate=shutil.which(CLOUDFLARED) or CLOUDFLARED
 return candidate if Path(candidate).is_file() and os.access(candidate,os.X_OK) else None
LOCKS={}; LOCKS_GUARD=threading.Lock()
class UserError(Exception): pass

def ensure_root(root=ROOT): root.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(root,0o700); return root
def meta_path(root,rid): return Path(root)/f"{rid}.state.json"
def private_path(root,rid): return Path(root)/f"{rid}.private.json"
def receipt_path(root,rid): return Path(root)/f"{rid}.receipt.json"
def log_path(root,rid): return Path(root)/f"{rid}.cloudflared.log"
def _atomic(path,data,mode=0o600):
 path=Path(path); path.parent.mkdir(parents=True,exist_ok=True); fd,tmp=tempfile.mkstemp(prefix=".handoff-",dir=str(path.parent))
 try:
  os.fchmod(fd,mode)
  with os.fdopen(fd,"w",encoding="utf-8",newline="") as f: f.write(data); f.flush(); os.fsync(f.fileno())
  os.replace(tmp,path); os.chmod(path,mode)
 finally:
  try: os.unlink(tmp)
  except FileNotFoundError: pass
def _read_json(path):
 with open(path,"r",encoding="utf-8") as f: return json.load(f)
def load_meta(root,rid): return _read_json(meta_path(root,rid))
def load_private(root,rid): return _read_json(private_path(root,rid))
def save_meta(root,meta):
 allowed={k:meta[k] for k in ("id","fields","plain","labels","created_at","expires_at","status","server_pid","server_identity","tunnel_pid","tunnel_identity","port") if k in meta}
 _atomic(meta_path(root,meta["id"]),json.dumps(allowed,separators=(",",":")))
def save_private(root,rid,data): _atomic(private_path(root,rid),json.dumps(data,separators=(",",":")))
def _lock(rid):
 with LOCKS_GUARD: return LOCKS.setdefault(rid,threading.Lock())
def validate_fields(fields):
 if not fields or len(fields)>MAX_FIELDS or len(set(fields))!=len(fields): raise UserError("invalid field list")
 if any(not KEY_RE.fullmatch(x) for x in fields): raise UserError("field names must be uppercase environment-style keys")
def new_metadata(root,fields,labels,plain,ttl):
 ensure_root(root); validate_fields(fields)
 if ttl<1 or ttl>86400: raise UserError("TTL must be between 1 and 86400 seconds")
 if set(labels)-set(fields) or set(plain)-set(fields): raise UserError("labels/plain names must be declared fields")
 rid=secrets.token_urlsafe(18); now=time.time(); cap=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
 meta={"id":rid,"fields":fields,"labels":labels,"plain":sorted(plain),"created_at":now,"expires_at":now+ttl,"status":"pending"}
 save_meta(root,meta); save_private(root,rid,{"capability":cap,"csrf":csrf}); return {**meta,"capability":cap,"csrf":csrf}
def _combined(root,rid): return {**load_meta(root,rid),**load_private(root,rid)}
def render_form(meta):
 controls=[]
 for name in meta["fields"]:
  label=html.escape(meta.get("labels",{}).get(name,name),quote=True); key=html.escape(name,quote=True); typ="text" if name in meta.get("plain",[]) else "password"; ac="off" if typ=="text" else "new-password"
  controls.append(f'<label class="field"><span>{label}</span><input type="{typ}" name="{key}" maxlength="{MAX_VALUE}" autocomplete="{ac}" spellcheck="false" required></label>')
 csrf=html.escape(meta["csrf"],quote=True)
 page='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Secure Secret Drop</title><style>
:root{color-scheme:light dark;--bg:#f2f7f6;--card:#fff;--text:#172321;--muted:#64736f;--line:#d8e3e0;--accent:#0f766e;--accent2:#115e59;--soft:#e8f5f2;--shadow:0 20px 55px rgba(18,55,50,.12)}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at top,#deefeb 0,var(--bg) 42%);color:var(--text);font:15px/1.5 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{width:min(100% - 32px,480px);margin:0 auto;padding:64px 0}.brand{display:flex;align-items:center;gap:12px;margin:0 0 18px}.mark{display:grid;place-items:center;width:40px;height:40px;border-radius:12px;background:var(--accent);color:#fff;font-size:20px;box-shadow:0 8px 22px rgba(15,118,110,.28)}.brand strong{font-size:15px;letter-spacing:.01em}.brand small{display:block;color:var(--muted)}.card{background:var(--card);border:1px solid rgba(95,125,119,.22);border-radius:20px;padding:30px;box-shadow:var(--shadow)}.eyebrow{display:inline-flex;align-items:center;gap:7px;margin:0 0 13px;padding:5px 9px;border-radius:999px;background:var(--soft);color:var(--accent);font-size:12px;font-weight:700;letter-spacing:.03em;text-transform:uppercase}.dot{width:6px;height:6px;border-radius:50%;background:#22a06b}h1{margin:0 0 8px;font-size:28px;line-height:1.2;letter-spacing:-.025em}.intro{margin:0 0 25px;color:var(--muted)}.field{display:block;margin:0 0 17px}.field span{display:block;margin:0 0 7px;font-size:13px;font-weight:650}input{display:block;width:100%;height:46px;padding:0 13px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--text);font:inherit;outline:none;transition:border-color .15s,box-shadow .15s}input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(15,118,110,.14)}button{width:100%;height:48px;margin-top:4px;border:0;border-radius:11px;background:var(--accent);color:#fff;font:700 15px/1 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;cursor:pointer;box-shadow:0 8px 20px rgba(15,118,110,.23)}button:hover{background:var(--accent2)}button:focus-visible{outline:3px solid rgba(15,118,110,.26);outline-offset:2px}.foot{margin:16px 0 0;text-align:center;color:var(--muted);font-size:12px}@media(max-width:520px){.shell{padding:30px 0}.card{padding:24px 20px;border-radius:16px}}@media(prefers-color-scheme:dark){:root{--bg:#0b1715;--card:#11211e;--text:#edf5f3;--muted:#9bada8;--line:#29413c;--accent:#5eead4;--accent2:#7cf2df;--soft:#173b35;--shadow:0 22px 60px rgba(0,0,0,.35)}body{background:radial-gradient(circle at top,#12332f 0,var(--bg) 45%)}button{color:#08211d}}
</style></head><body><main class="shell"><div class="brand"><div class="mark" aria-hidden="true">&#128274;</div><div><strong>Secure Secret Drop</strong><small>Private one-time handoff</small></div></div><section class="card"><div class="eyebrow"><i class="dot"></i>One-time secure drop</div><h1>Enter the requested values</h1><p class="intro">This form accepts one submission then disappears.</p><form method="post" autocomplete="off"><input type="hidden" name="csrf" value="'''+csrf+'">'+"".join(controls)+'''<button type="submit">Submit securely</button></form></section><p class="foot">Protected in transit by HTTPS</p></main></body></html>'''
 return page.encode()
def render_confirmation():
 return b'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>Drop received</title><style>:root{color-scheme:light dark;--bg:#f2f7f6;--card:#fff;--text:#172321;--muted:#64736f;--green:#15805f;--soft:#e8f5f2}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at top,#deefeb 0,var(--bg) 48%);color:var(--text);font:15px/1.5 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.card{width:min(100%,440px);padding:38px 30px;text-align:center;background:var(--card);border:1px solid rgba(95,125,119,.22);border-radius:20px;box-shadow:0 20px 55px rgba(18,55,50,.12)}.check{display:grid;place-items:center;width:54px;height:54px;margin:0 auto 18px;border-radius:50%;background:var(--soft);color:var(--green);font-size:27px;font-weight:800}h1{margin:0 0 8px;font-size:27px;letter-spacing:-.025em}p{margin:0;color:var(--muted)}@media(prefers-color-scheme:dark){:root{--bg:#0b1715;--card:#11211e;--text:#edf5f3;--muted:#9bada8;--soft:#173b35}body{background:radial-gradient(circle at top,#12332f 0,var(--bg) 52%)}}</style></head><body><main class="card confirmation"><div class="check" aria-hidden="true">&#10003;</div><h1>Drop received</h1><p>Your values were submitted successfully.<br>You can safely close this page.</p></main></body></html>'''
def _headers(handler,ctype="text/html; charset=utf-8"):
 handler.send_header("Content-Type",ctype); handler.send_header("Cache-Control","no-store"); handler.send_header("Pragma","no-cache"); handler.send_header("Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"); handler.send_header("X-Frame-Options","DENY"); handler.send_header("Referrer-Policy","no-referrer"); handler.send_header("X-Content-Type-Options","nosniff")
def _reply(handler,code,body=b"",head=False): handler.send_response(code); _headers(handler); handler.send_header("Content-Length",str(len(body))); handler.end_headers(); (None if head else handler.wfile.write(body))
def store_submission(root,rid,values):
 with _lock(rid):
  meta=load_meta(root,rid)
  if meta["status"]!="pending": raise UserError("gone")
  if time.time()>=meta["expires_at"]: meta["status"]="expired"; save_meta(root,meta); _cleanup_data(root,rid); raise UserError("gone")
  _atomic(receipt_path(root,rid),json.dumps(values,separators=(",",":"))); meta["status"]="submitted"; save_meta(root,meta)
  try: private_path(root,rid).unlink()
  except FileNotFoundError: pass
class Server(http.server.ThreadingHTTPServer):
 daemon_threads=True; allow_reuse_address=False
 def __init__(self,addr,root,rid,auto_stop=False): self.root=Path(root); self.rid=rid; self.auto_stop=auto_stop; super().__init__(addr,Handler)
class Handler(http.server.BaseHTTPRequestHandler):
 protocol_version="HTTP/1.1"
 def log_message(self,*args): pass
 def _meta(self):
  try: return _combined(self.server.root,self.server.rid)
  except (FileNotFoundError,json.JSONDecodeError): return None
 def _valid_path(self,m): return m and self.path.split("?",1)[0]=="/"+m["capability"]
 def do_HEAD(self): self._read(False,True)
 def do_GET(self): self._read(True,False)
 def _read(self,send,head):
  m=self._meta()
  if not self._valid_path(m): return _reply(self,404,b"Not found",head)
  state=load_meta(self.server.root,self.server.rid)
  if time.time()>=state["expires_at"] or state["status"]!="pending": return _reply(self,410,b"Gone",head)
  body=render_form(m); _reply(self,200,body,head)
 def do_POST(self):
  m=self._meta()
  if not self._valid_path(m): return _reply(self,404,b"Not found")
  try: n=int(self.headers.get("Content-Length","-1"))
  except ValueError: n=-1
  if n<0: return _reply(self,411,b"Length required")
  if n>MAX_BODY: return _reply(self,413,b"Too large")
  if self.headers.get("Content-Type","").split(";",1)[0].strip().lower()!="application/x-www-form-urlencoded": return _reply(self,415,b"Unsupported")
  raw=self.rfile.read(n)
  try: pairs=urllib.parse.parse_qsl(raw.decode("utf-8","strict"),keep_blank_values=True,max_num_fields=MAX_FIELDS+1,strict_parsing=True)
  except (UnicodeError,ValueError): return _reply(self,400,b"Invalid form")
  names=[k for k,v in pairs]; expected=["csrf",*m["fields"]]
  if len(names)!=len(set(names)) or set(names)!=set(expected): return _reply(self,400,b"Invalid fields")
  vals=dict(pairs)
  if not secrets.compare_digest(vals["csrf"],m["csrf"]): return _reply(self,403,b"Forbidden")
  values={k:vals[k] for k in m["fields"]}
  if any(len(k)>64 or len(v.encode("utf-8"))>MAX_VALUE for k,v in values.items()): return _reply(self,413,b"Too large")
  try: store_submission(self.server.root,self.server.rid,values)
  except UserError: return _reply(self,410,b"Gone")
  _reply(self,200,render_confirmation())
  if self.server.auto_stop: threading.Thread(target=lambda:(time.sleep(.25),self.server.shutdown()),daemon=True).start()
def start_local_server(root,rid,auto_stop=False):
 srv=Server(("127.0.0.1",0),root,rid,auto_stop); t=threading.Thread(target=srv.serve_forever,daemon=True); t.start(); return srv,t
def status_record(root,rid):
 meta=load_meta(root,rid)
 if meta["status"]=="pending" and time.time()>=meta["expires_at"]:
  meta["status"]="expired"; save_meta(root,meta); _cleanup_data(root,rid)
 return {"id":rid,"status":meta["status"],"fields":meta["fields"],"expires_at":meta["expires_at"]}
def pid_matches(pid,identity):
 if not isinstance(pid,int) or pid<=1 or not identity: return False
 try: cmd=subprocess.check_output(["ps","-p",str(pid),"-o","command="],text=True,stderr=subprocess.DEVNULL).strip()
 except (subprocess.SubprocessError,OSError): return False
 return all(token and token in cmd for token in identity.split("|"))
def safe_kill(pid,identity):
 if not pid_matches(pid,identity): return False
 try: os.kill(pid,signal.SIGTERM); return True
 except (ProcessLookupError,PermissionError): return False
def _cleanup_data(root,rid):
 for p in (private_path(root,rid),receipt_path(root,rid)):
  try: p.unlink()
  except FileNotFoundError: pass
def _kill_children(meta):
 safe_kill(meta.get("tunnel_pid",0),meta.get("tunnel_identity","")); safe_kill(meta.get("server_pid",0),meta.get("server_identity",""))
def _atomic_destination(path,text): _atomic(Path(path).expanduser(),text,0o600)
def consume(root,rid,env_file=None,json_file=None,discard=False,overwrite=False):
 choices=sum(x is not None and x is not False for x in (env_file,json_file,discard))
 if choices!=1: raise UserError("choose exactly one destination")
 meta=load_meta(root,rid)
 if meta["status"]!="submitted" or not receipt_path(root,rid).exists(): raise UserError("receipt is not submitted")
 values=_read_json(receipt_path(root,rid))
 if set(values)!=set(meta["fields"]): raise UserError("receipt validation failed")
 if env_file is not None:
  p=Path(env_file).expanduser(); lines=p.read_text(encoding="utf-8").splitlines() if p.exists() else []; indexes={}
  for i,line in enumerate(lines):
   if not line or line.lstrip().startswith("#") or "=" not in line: continue
   key=line.split("=",1)[0]
   if KEY_RE.fullmatch(key): indexes[key]=i
  collisions=set(indexes)&set(values)
  if collisions and not overwrite: raise UserError("destination already contains requested keys; use --overwrite")
  for k in meta["fields"]:
   if "\n" in values[k] or "\r" in values[k]: raise UserError("env values may not contain newlines")
   row=f"{k}={values[k]}"
   if k in indexes: lines[indexes[k]]=row
   else: lines.append(row)
  _atomic_destination(p,"\n".join(lines)+"\n")
 elif json_file is not None:
  p=Path(json_file).expanduser()
  try: obj=json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
  except (json.JSONDecodeError,UnicodeError): raise UserError("destination is not valid JSON")
  if not isinstance(obj,dict): raise UserError("JSON destination must contain an object")
  if set(obj)&set(values) and not overwrite: raise UserError("destination already contains requested keys; use --overwrite")
  obj.update(values); _atomic_destination(p,json.dumps(obj,indent=2,ensure_ascii=False)+"\n")
 meta["status"]="consumed"; save_meta(root,meta); _cleanup_data(root,rid); _kill_children(meta)
def cancel(root,rid):
 meta=load_meta(root,rid)
 if meta["status"] in ("consumed","expired","cancelled"): raise UserError("handoff is already closed")
 meta["status"]="cancelled"; save_meta(root,meta); _cleanup_data(root,rid); _kill_children(meta)
def resolve_a(host,timeout=3):
 try:
  query="https://dns.google/resolve?"+urllib.parse.urlencode({"name":host,"type":"A"})
  req=urllib.request.Request(query,headers={"Accept":"application/dns-json"})
  with urllib.request.urlopen(req,timeout=timeout) as response: data=json.load(response)
  return [item["data"] for item in data.get("Answer",[]) if item.get("type")==1 and isinstance(item.get("data"),str)]
 except Exception: return []
def head_via_ip(url,ip,timeout=3):
 parsed=urllib.parse.urlsplit(url)
 if parsed.scheme!="https" or not parsed.hostname: return False
 raw=None; conn=None
 try:
  raw=socket.create_connection((ip,parsed.port or 443),timeout=timeout)
  tls=ssl.create_default_context().wrap_socket(raw,server_hostname=parsed.hostname); raw=None
  conn=http.client.HTTPSConnection(parsed.hostname,parsed.port or 443,timeout=timeout,context=ssl.create_default_context()); conn.sock=tls
  target=urllib.parse.urlunsplit(("","",parsed.path or "/",parsed.query,"")); conn.request("HEAD",target,headers={"Host":parsed.netloc,"Connection":"close"}); response=conn.getresponse(); response.read(); return response.status==200
 except Exception: return False
 finally:
  if conn:
   try: conn.close()
   except Exception: pass
  if raw:
   try: raw.close()
   except Exception: pass
def public_ready(url,timeout=2):
 try:
  req=urllib.request.Request(url,method="HEAD")
  with urllib.request.urlopen(req,timeout=timeout) as response: return response.status==200
 except urllib.error.URLError as error:
  if not isinstance(error.reason,socket.gaierror): return False
  host=urllib.parse.urlsplit(url).hostname
  return bool(host) and any(head_via_ip(url,ip,timeout) for ip in resolve_a(host,timeout))
 except Exception: return False
def _serve(root,rid):
 srv=Server(("127.0.0.1",0),root,rid,True); serve_thread=threading.Thread(target=srv.serve_forever,daemon=True); serve_thread.start(); meta=load_meta(root,rid); meta.update(server_pid=os.getpid(),server_identity=f"handoff.py|_serve|{rid}",port=srv.server_address[1]); save_meta(root,meta)
 lp=log_path(root,rid); log=open(lp,"a",encoding="utf-8"); os.chmod(lp,0o600); proc=None; tunnel_identity=f"cloudflared|--config /dev/null|http://127.0.0.1:{srv.server_address[1]}"
 try:
  full_url=None
  for attempt in range(1,5):
   cmd=[CLOUDFLARED,"tunnel","--no-autoupdate","--config","/dev/null","--url",f"http://127.0.0.1:{srv.server_address[1]}"]
   marker=lp.stat().st_size
   proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
   meta=load_meta(root,rid); meta.update(tunnel_pid=proc.pid,tunnel_identity=tunnel_identity); save_meta(root,meta)
   deadline=time.time()+18; url=None; registered=False
   while time.time()<deadline and proc.poll() is None:
    log.flush()
    try: txt=lp.read_text(encoding="utf-8",errors="replace")[marker:]
    except OSError: txt=""
    found=re.search(r"https://[a-z0-9-]+\.trycloudflare\.com",txt)
    if found: url=found.group(0)
    registered="Registered tunnel connection" in txt
    if url and registered: break
    time.sleep(.1)
   if url and registered:
    priv=load_private(root,rid); candidate=url+"/"+priv["capability"]
    ready_deadline=time.time()+12
    while time.time()<ready_deadline and proc.poll() is None:
     if public_ready(candidate,3): full_url=candidate; break
     time.sleep(.5)
   if full_url: break
   safe_kill(proc.pid,tunnel_identity)
   try: proc.wait(timeout=5)
   except subprocess.TimeoutExpired:
    if pid_matches(proc.pid,tunnel_identity): proc.kill()
   proc=None
  if not full_url: meta=load_meta(root,rid); meta["status"]="failed"; save_meta(root,meta); return 2
  priv=load_private(root,rid); priv["url"]=full_url; save_private(root,rid,priv)
  meta=load_meta(root,rid); requested_ttl=meta["expires_at"]-meta["created_at"]; meta["expires_at"]=time.time()+requested_ttl; save_meta(root,meta)
  timer=threading.Timer(requested_ttl,srv.shutdown); timer.daemon=True; timer.start(); serve_thread.join(); timer.cancel()
 finally:
  if serve_thread.is_alive(): srv.shutdown(); serve_thread.join(timeout=5)
  srv.server_close()
  if proc is not None:
   safe_kill(proc.pid,tunnel_identity)
   try: proc.wait(timeout=5)
   except subprocess.TimeoutExpired:
    if pid_matches(proc.pid,tunnel_identity): proc.kill()
  log.close(); current=load_meta(root,rid)
  if current["status"]=="pending": current["status"]="expired"; save_meta(root,current); _cleanup_data(root,rid)
 return 0
def create(args):
 if not resolved_cloudflared(): raise UserError("cloudflared is required; run doctor and follow its setup guide")
 root=ensure_root(Path(args.root).expanduser()); labels={}
 for item in args.label:
  if "=" not in item: raise UserError("labels must be NAME=Label")
  k,v=item.split("=",1); labels[k]=v
 meta=new_metadata(root,args.field,labels,set(args.plain),args.ttl)
 cmd=[sys.executable,str(Path(__file__).resolve()),"--root",str(root),"_serve",meta["id"]]
 with open(os.devnull,"rb") as devin, open(os.devnull,"ab") as devout: subprocess.Popen(cmd,stdin=devin,stdout=devout,stderr=devout,start_new_session=True,close_fds=True)
 deadline=time.time()+args.ready_timeout
 while time.time()<deadline:
  try:
   state=load_meta(root,meta["id"]); priv=load_private(root,meta["id"])
   if priv.get("url") and public_ready(priv["url"]): print(f"receipt_id={meta['id']}\nurl={priv['url']}\nfields={','.join(meta['fields'])}\nstatus=pending"); return
   if state["status"]=="failed": break
  except (FileNotFoundError,json.JSONDecodeError): pass
  time.sleep(.1)
 try: cancel(root,meta["id"])
 except UserError: pass
 raise UserError("tunnel did not become ready")
def doctor():
 resolved=resolved_cloudflared(); ok=bool(resolved)
 lines=["python=ok",f"cloudflared={'ok' if ok else 'missing'}"]
 if ok: lines.append(f"cloudflared_path={resolved}")
 else: lines.extend(["cloudflared_required=true",f"setup_guide={Path(__file__).parents[1]/'references'/'cloudflared-setup.md'}"])
 lines.append(f"state_directory={ROOT}"); print("\n".join(lines)); return 0 if ok else 1
def parser():
 p=argparse.ArgumentParser(); p.add_argument("--root",default=str(ROOT)); sub=p.add_subparsers(dest="cmd",required=True)
 c=sub.add_parser("create"); c.add_argument("--field",action="append",required=True); c.add_argument("--label",action="append",default=[]); c.add_argument("--plain",action="append",default=[]); c.add_argument("--ttl",type=int,default=600); c.add_argument("--ready-timeout",type=float,default=140)
 s=sub.add_parser("status"); s.add_argument("id"); x=sub.add_parser("consume"); x.add_argument("id"); g=x.add_mutually_exclusive_group(required=True); g.add_argument("--env-file"); g.add_argument("--json-file"); g.add_argument("--discard",action="store_true"); x.add_argument("--overwrite",action="store_true")
 z=sub.add_parser("cancel"); z.add_argument("id"); sub.add_parser("doctor"); q=sub.add_parser("_serve"); q.add_argument("id")
 return p
def main():
 args=parser().parse_args(); root=Path(args.root).expanduser()
 try:
  if args.cmd=="create": create(args)
  elif args.cmd=="status":
   r=status_record(root,args.id); print(f"receipt_id={r['id']}\nstatus={r['status']}\nfields={','.join(r['fields'])}\nexpires_at={time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(r['expires_at']))}")
  elif args.cmd=="consume": consume(root,args.id,args.env_file,args.json_file,args.discard,args.overwrite); print(f"receipt_id={args.id}\nstatus=consumed")
  elif args.cmd=="cancel": cancel(root,args.id); print(f"receipt_id={args.id}\nstatus=cancelled")
  elif args.cmd=="doctor": return doctor()
  else: return _serve(root,args.id)
 except (UserError,FileNotFoundError,PermissionError) as e: print(f"error={str(e)}",file=sys.stderr); return 2
 return 0
if __name__=="__main__": raise SystemExit(main())
