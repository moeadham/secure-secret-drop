import contextlib, http.client, importlib.util, io, json, os, socket, stat, sys, tempfile, threading, time, unittest, urllib.error, urllib.parse
from unittest import mock
from pathlib import Path
SCRIPT=Path(__file__).parents[1]/"scripts"/"handoff.py"; spec=importlib.util.spec_from_file_location("handoff",SCRIPT); h=importlib.util.module_from_spec(spec); sys.modules["handoff"]=h; spec.loader.exec_module(h)
class HandoffTests(unittest.TestCase):
 def setUp(self):
  self.td=tempfile.TemporaryDirectory(); self.root=Path(self.td.name)/"state"; self.root.mkdir(mode=0o700); self.fields=["TEST_API_KEY","TEST_API_SECRET"]
  self.meta=h.new_metadata(self.root,self.fields,{"TEST_API_KEY":"<Key & more>"},set(),60); self.server,self.thread=h.start_local_server(self.root,self.meta["id"]); self.port=self.server.server_address[1]
 def tearDown(self): self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2); self.td.cleanup()
 def req(self,method,path=None,body=None,headers=None):
  c=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3); c.request(method,path or "/"+self.meta["capability"],body=body,headers=headers or {}); r=c.getresponse(); data=r.read(); hs=dict(r.getheaders()); c.close(); return r.status,hs,data
 def post(self,pairs,path=None):
  body=urllib.parse.urlencode(pairs); return self.req("POST",path,body,{"Content-Type":"application/x-www-form-urlencoded","Content-Length":str(len(body))})
 def test_get_and_head_do_not_consume_and_headers_escape(self):
  for method in ("GET","HEAD"):
   status,headers,_=self.req(method); self.assertEqual(200,status); self.assertEqual("no-store",headers["Cache-Control"]); self.assertIn("default-src 'none'",headers["Content-Security-Policy"]); self.assertEqual("DENY",headers["X-Frame-Options"]); self.assertEqual("no-referrer",headers["Referrer-Policy"]); self.assertEqual("nosniff",headers["X-Content-Type-Options"]); self.assertEqual("pending",h.load_meta(self.root,self.meta["id"])["status"])
  self.assertIn(b"&lt;Key &amp; more&gt;",self.req("GET")[2]); self.assertIn(b'type="password"',self.req("GET")[2])
  page=self.req("GET")[2]; self.assertIn(b'class="shell"',page); self.assertIn(b'class="card"',page); self.assertIn(b'One-time secure drop',page); self.assertIn(b'Submit securely',page); self.assertIn(b'This form accepts one submission then disappears.',page); self.assertNotIn(b'Short-lived and private',page); self.assertNotIn(b'No values are stored in this page',page); self.assertIn(b'#0f766e',page); self.assertNotIn(b'#3157d5',page)
 def test_wrong_path_and_validation(self):
  self.assertEqual(404,self.req("GET","/wrong")[0]); base=[("csrf",self.meta["csrf"]),("TEST_API_KEY","a"),("TEST_API_SECRET","b")]; self.assertEqual(403,self.post([("csrf","wrong"),*base[1:]])[0]); self.assertEqual(400,self.post(base+[("EXTRA","x")])[0]); self.assertEqual(400,self.post(base+[("TEST_API_KEY","again")])[0]); self.assertEqual(400,self.post(base[:-1])[0]); self.assertEqual("pending",h.load_meta(self.root,self.meta["id"])["status"])
 def test_body_limits_and_content_type(self):
  self.assertEqual(413,self.req("POST",body=b"x"*(h.MAX_BODY+1),headers={"Content-Length":str(h.MAX_BODY+1),"Content-Type":"application/x-www-form-urlencoded"})[0]); self.assertEqual(415,self.req("POST",body=b"{}",headers={"Content-Length":"2","Content-Type":"application/json"})[0])
 def test_submission_confirmation_is_styled(self):
  pairs=[("csrf",self.meta["csrf"]),("TEST_API_KEY","a"),("TEST_API_SECRET","b")]; status,_,body=self.post(pairs); self.assertEqual(200,status); self.assertIn(b'Drop received',body); self.assertIn(b'class="card confirmation"',body)
 def test_single_post_is_atomic_under_race(self):
  pairs=[("csrf",self.meta["csrf"]),("TEST_API_KEY","a"),("TEST_API_SECRET","b")]; barrier=threading.Barrier(3); results=[]
  def go(): barrier.wait(); results.append(self.post(pairs)[0])
  ts=[threading.Thread(target=go) for _ in range(2)]; [t.start() for t in ts]; barrier.wait(); [t.join() for t in ts]; self.assertEqual([200,410],sorted(results)); self.assertEqual("submitted",h.load_meta(self.root,self.meta["id"])["status"]); self.assertEqual(0o600,stat.S_IMODE(h.receipt_path(self.root,self.meta["id"]).stat().st_mode))
 def test_expiry(self):
  meta=h.load_meta(self.root,self.meta["id"]); meta["expires_at"]=time.time()-1; h.save_meta(self.root,meta); self.assertEqual(410,self.req("GET")[0]); self.assertEqual("expired",h.status_record(self.root,self.meta["id"])["status"])
 def test_plain_input_and_permissions(self):
  self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2); meta=h.new_metadata(self.root,["PUBLIC_NOTE"],{}, {"PUBLIC_NOTE"},60); raw=h.render_form(meta).decode(); self.assertIn('type="text"',raw); self.assertEqual(0o700,stat.S_IMODE(self.root.stat().st_mode)); self.assertEqual(0o600,stat.S_IMODE(h.meta_path(self.root,meta["id"]).stat().st_mode))
 def test_destination_merge_no_overwrite_and_retry(self):
  h.store_submission(self.root,self.meta["id"],{"TEST_API_KEY":"a","TEST_API_SECRET":"b"}); env=Path(self.td.name)/"target.env"; env.write_text("TEST_API_KEY=old\nOTHER=keep\n"); os.chmod(env,0o600)
  with self.assertRaises(h.UserError): h.consume(self.root,self.meta["id"],env_file=env)
  self.assertTrue(h.receipt_path(self.root,self.meta["id"]).exists()); h.consume(self.root,self.meta["id"],env_file=env,overwrite=True); self.assertEqual("TEST_API_KEY=a\nOTHER=keep\nTEST_API_SECRET=b\n",env.read_text()); self.assertEqual(0o600,stat.S_IMODE(env.stat().st_mode)); self.assertFalse(h.receipt_path(self.root,self.meta["id"]).exists()); self.assertEqual("consumed",h.status_record(self.root,self.meta["id"])["status"])
 def test_json_merge_and_discard(self):
  h.store_submission(self.root,self.meta["id"],{"TEST_API_KEY":"a","TEST_API_SECRET":"b"}); dest=Path(self.td.name)/"x.json"; dest.write_text('{"OTHER":"keep"}'); h.consume(self.root,self.meta["id"],json_file=dest); self.assertEqual({"OTHER":"keep","TEST_API_KEY":"a","TEST_API_SECRET":"b"},json.loads(dest.read_text()))
 def test_pid_identity_validation(self):
  self.assertTrue(h.pid_matches(os.getpid(),"Python|test_handoff.py")); self.assertFalse(h.pid_matches(os.getpid(),"Python|definitely-not-this-process")); self.assertFalse(h.safe_kill(os.getpid(),"Python|definitely-not-this-process"))
 def test_public_readiness_probe(self):
  self.assertTrue(h.public_ready(f"http://127.0.0.1:{self.port}/{self.meta['capability']}")); self.assertFalse(h.public_ready("http://127.0.0.1:1/nope",.1))
 def test_public_readiness_falls_back_when_local_dns_is_negative_cached(self):
  dns_error=urllib.error.URLError(socket.gaierror(8,"not known"))
  with mock.patch.object(h.urllib.request,"urlopen",side_effect=dns_error), mock.patch.object(h,"resolve_a",return_value=["104.16.1.1"]), mock.patch.object(h,"head_via_ip",return_value=True) as probe:
   self.assertTrue(h.public_ready("https://fresh.trycloudflare.com/cap",.1)); probe.assert_called_once()
 def test_cloudflared_discovery_prefers_explicit_override(self):
  binary=Path(self.td.name)/"custom-cloudflared"; binary.write_text("#!/bin/sh\nexit 0\n"); os.chmod(binary,0o700)
  with mock.patch.dict(os.environ,{"CLOUDFLARED_BIN":str(binary)}): self.assertEqual(str(binary),h.find_cloudflared())
 def test_state_directory_is_agent_neutral_and_configurable(self):
  custom=Path(self.td.name)/"state-override"
  with mock.patch.dict(os.environ,{"SECURE_SECRET_DROP_STATE_DIR":str(custom)}): self.assertEqual(custom,h.default_root())
 def test_doctor_reports_missing_dependency_and_setup_guide(self):
  out=io.StringIO()
  with mock.patch.object(h,"CLOUDFLARED",str(Path(self.td.name)/"missing")), contextlib.redirect_stdout(out): self.assertEqual(1,h.doctor())
  text=out.getvalue(); self.assertIn("cloudflared=missing",text); self.assertIn("cloudflared_required=true",text); self.assertIn("cloudflared-setup.md",text)
 def test_secret_absent_from_cli_output(self):
  h.store_submission(self.root,self.meta["id"],{"TEST_API_KEY":"sensitive-one","TEST_API_SECRET":"sensitive-two"}); out=io.StringIO(); err=io.StringIO()
  with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err): h.consume(self.root,self.meta["id"],discard=True)
  text=out.getvalue()+err.getvalue(); self.assertNotIn("sensitive-one",text); self.assertNotIn("sensitive-two",text)
if __name__=="__main__": unittest.main(verbosity=2)
