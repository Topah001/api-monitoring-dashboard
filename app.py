"""A small local HTTP GET monitor with DNS pinning and strict public-target validation."""
from __future__ import annotations
import http.client, ipaddress, json, os, socket, sqlite3, ssl, threading, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

DB_PATH=Path(os.environ.get('API_MONITOR_DB',Path(__file__).with_name('monitor.db')))
MAX_TIMEOUT=30


from contextlib import contextmanager
@contextmanager
def connect(path=DB_PATH):
    db=sqlite3.connect(path,timeout=10); db.row_factory=sqlite3.Row
    try:
        with db: yield db
    finally: db.close()

def initialize(path=DB_PATH):
    with connect(path) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY,url TEXT NOT NULL,timeout REAL NOT NULL,interval_seconds INTEGER NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL)''')
        db.execute('''CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY,check_id INTEGER NOT NULL REFERENCES checks(id) ON DELETE CASCADE,checked_at TEXT NOT NULL,status_code INTEGER,latency_ms REAL,ok INTEGER NOT NULL,error TEXT)''')

def resolve_public(host,port):
    """Resolve once and reject the whole host if any answer is not globally routable."""
    if '%' in host: raise ValueError('Scoped IP addresses are not allowed.')
    try: literal=ipaddress.ip_address(host)
    except ValueError: literal=None
    if literal:
        addresses=[literal.compressed]
    else:
        try: addresses=list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)))
        except socket.gaierror as exc: raise ValueError('Host name could not be resolved.') from exc
    if not addresses: raise ValueError('Host name has no usable address.')
    for address in addresses:
        try: parsed=ipaddress.ip_address(address)
        except ValueError as exc: raise ValueError('Host resolved to an invalid address.') from exc
        if not parsed.is_global: raise ValueError('Only globally routable public addresses are allowed; private, loopback, link-local, and reserved targets are blocked.')
    return addresses

def validate_url(url,timeout=10):
    if not isinstance(url,str) or not url or len(url)>2048 or any(ord(c)<32 or ord(c)==127 for c in url): raise ValueError('Enter a valid HTTP or HTTPS URL (maximum 2048 characters).')
    try: parts=urlsplit(url); port=parts.port
    except ValueError as exc: raise ValueError('URL or port is invalid.') from exc
    if parts.scheme.lower() not in ('http','https') or not parts.hostname: raise ValueError('Only explicit http:// and https:// URLs are supported.')
    if parts.username is not None or parts.password is not None: raise ValueError('URLs containing user credentials are not allowed.')
    if parts.fragment: raise ValueError('URL fragments are not sent to a server; remove the fragment.')
    host=parts.hostname
    if host.lower().rstrip('.') in ('localhost','localhost.localdomain') or host.lower().endswith('.localhost'): raise ValueError('Localhost targets are blocked.')
    try: host=ipaddress.ip_address(host).compressed
    except ValueError:
        try: host=host.encode('idna').decode('ascii').lower().rstrip('.')
        except UnicodeError as exc: raise ValueError('Host name is invalid.') from exc
        if not host or len(host)>253 or any(not label or len(label)>63 or label.startswith('-') or label.endswith('-') for label in host.split('.')): raise ValueError('Host name is invalid.')
    port=port or (443 if parts.scheme.lower()=='https' else 80)
    if not 1<=port<=65535: raise ValueError('Port must be between 1 and 65535.')
    if not isinstance(timeout,(int,float)) or not 0.1<=float(timeout)<=MAX_TIMEOUT: raise ValueError('Timeout must be between 0.1 and 30 seconds.')
    addresses=resolve_public(host,port)
    path=parts.path or '/'
    if parts.query: path+='?'+parts.query
    return {'url':url,'scheme':parts.scheme.lower(),'host':host,'port':port,'path':path,'addresses':addresses}

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self,host,port,ip,timeout,context):
        super().__init__(ip,port,timeout=timeout,context=context); self.original_host=host
    def connect(self):
        sock=socket.create_connection((self.host,self.port),self.timeout,self.source_address)
        self.sock=self._context.wrap_socket(sock,server_hostname=self.original_host)

def request_once(target,timeout):
    address=target['addresses'][0]
    if target['scheme']=='https': conn=PinnedHTTPSConnection(target['host'],target['port'],address,timeout,ssl.create_default_context())
    else: conn=http.client.HTTPConnection(address,target['port'],timeout=timeout)
    host_header=f"[{target['host']}]" if ':' in target['host'] else target['host']
    default_port=443 if target['scheme']=='https' else 80
    if target['port']!=default_port: host_header+=f":{target['port']}"
    try:
        conn.request('GET',target['path'],headers={'Host':host_header,'User-Agent':'Local-API-Monitor/1.0','Connection':'close'})
        response=conn.getresponse(); status=response.status; response.read(65536); return status
    finally: conn.close()

def check_url(url,timeout=10,transport=None):
    start=time.perf_counter()
    try:
        target=validate_url(url,timeout)
        status=(transport(target,float(timeout)) if transport else request_once(target,float(timeout)))
        return {'status_code':int(status),'latency_ms':round((time.perf_counter()-start)*1000,2),'ok':200<=int(status)<400,'error':None}
    except Exception as exc:
        return {'status_code':None,'latency_ms':round((time.perf_counter()-start)*1000,2),'ok':False,'error':str(exc)[:240]}

def create_check(data,path=DB_PATH):
    url=str(data.get('url','')).strip(); timeout=float(data.get('timeout',10)); interval=int(data.get('interval_seconds',60))
    validate_url(url,timeout)
    if not 5<=interval<=86400: raise ValueError('Interval must be between 5 seconds and 24 hours.')
    with connect(path) as db:
        cur=db.execute('INSERT INTO checks(url,timeout,interval_seconds,enabled,created_at) VALUES(?,?,?,?,?)',(url,timeout,interval,1,datetime.now(timezone.utc).isoformat()))
        return dict(db.execute('SELECT * FROM checks WHERE id=?',(cur.lastrowid,)).fetchone())
def list_checks(path=DB_PATH):
    with connect(path) as db: return [dict(r) for r in db.execute('SELECT c.*, (SELECT ok FROM history h WHERE h.check_id=c.id ORDER BY id DESC LIMIT 1) AS last_ok, (SELECT status_code FROM history h WHERE h.check_id=c.id ORDER BY id DESC LIMIT 1) AS last_status, (SELECT latency_ms FROM history h WHERE h.check_id=c.id ORDER BY id DESC LIMIT 1) AS last_latency, (SELECT ROUND(100.0*AVG(ok),1) FROM history h WHERE h.check_id=c.id) AS availability_pct FROM checks c ORDER BY c.id DESC')]
def run_check(check_id,path=DB_PATH,transport=None):
    with connect(path) as db: row=db.execute('SELECT * FROM checks WHERE id=?',(check_id,)).fetchone()
    if row is None: raise KeyError('Check not found.')
    result=check_url(row['url'],row['timeout'],transport)
    with connect(path) as db:
        db.execute('INSERT INTO history(check_id,checked_at,status_code,latency_ms,ok,error) VALUES(?,?,?,?,?,?)',(check_id,datetime.now(timezone.utc).isoformat(),result['status_code'],result['latency_ms'],int(result['ok']),result['error']))
    return result
def get_history(check_id,path=DB_PATH,limit=100):
    with connect(path) as db:
        if not db.execute('SELECT 1 FROM checks WHERE id=?',(check_id,)).fetchone(): raise KeyError('Check not found.')
        return [dict(r) for r in db.execute('SELECT * FROM history WHERE check_id=? ORDER BY id DESC LIMIT ?',(check_id,min(500,max(1,limit))))]
def set_enabled(check_id,enabled,path=DB_PATH):
    with connect(path) as db:
        cur=db.execute('UPDATE checks SET enabled=? WHERE id=?',(int(bool(enabled)),check_id))
        if not cur.rowcount: raise KeyError('Check not found.')

def monitor_loop(stop_event,path=DB_PATH):
    last={}
    while not stop_event.wait(2):
        try: checks=list_checks(path)
        except sqlite3.Error: continue
        now=time.monotonic()
        for item in checks:
            if item['enabled'] and now-last.get(item['id'],0)>=item['interval_seconds']:
                try: run_check(item['id'],path)
                except (KeyError,sqlite3.Error): pass
                last[item['id']]=time.monotonic()

PAGE='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pulse · API Monitor</title><style>:root{font:16px/1.5 system-ui;color:#182e45;background:#f3f6fb}*{box-sizing:border-box}body{margin:0}.hero{background:#122b46;color:white;padding:3rem max(5vw,24px)}.hero h1{font-size:clamp(2.3rem,5vw,4rem);margin:.1em 0}.hero p{color:#c7d7e8;max-width:700px}.wrap{max-width:1100px;margin:28px auto;padding:0 20px}.grid{display:grid;grid-template-columns:330px 1fr;gap:22px}.panel,.card{background:white;border:1px solid #e1e8f0;border-radius:16px;padding:22px;box-shadow:0 10px 30px #18395d0a}.panel{height:max-content}label{font-size:.9rem;font-weight:650}input{display:block;width:100%;padding:11px;margin:5px 0 14px;border:1px solid #cbd7e4;border-radius:9px;font:inherit}button{border:0;background:#2365a0;color:white;border-radius:9px;padding:10px 14px;font:inherit;cursor:pointer}.secondary{background:#eaf2fa;color:#205985}.card{margin:12px 0}.row{display:flex;justify-content:space-between;align-items:center;gap:12px}.sub{color:#6d7f91;font-size:.88rem;overflow-wrap:anywhere}.pill{display:inline-block;padding:3px 10px;border-radius:30px;font-size:.8rem;background:#edf1f4}.up{color:#14794f;background:#e6f6ee}.down{color:#b33434;background:#fff0ed}.history{font-size:.86rem;border-top:1px solid #edf0f4;margin-top:14px;padding-top:10px}.small{font-size:.82rem;color:#617285}.msg{color:#b33}.empty{padding:30px;text-align:center;color:#708093}@media(max-width:760px){.grid{grid-template-columns:1fr}}</style></head><body><header class="hero"><div>LOCAL SERVICE OPERATIONS</div><h1>Pulse API Monitor</h1><p>Observe the status and response time of services you are authorized to monitor. Checks run on a schedule while this local app is running.</p></header><main class="wrap"><div class="grid"><section class="panel"><h2>Add a GET check</h2><form id="form"><label>Explicit service URL</label><input name="url" type="url" required placeholder="https://api.example.com/health"><label>Timeout (seconds, 0.1–30)</label><input name="timeout" type="number" min="0.1" max="30" step="0.1" value="10"><label>Interval (seconds, 5–86400)</label><input name="interval_seconds" type="number" min="5" max="86400" value="60"><button>Add monitor</button><p class="msg" id="msg"></p></form><p class="small">Targets must resolve only to globally routable public IP addresses. Local, private, link-local, reserved, and metadata targets are blocked. Redirects are not followed. Only explicit URLs are checked; there is no network discovery or scanning.</p></section><section><div class="row"><div><h2>Monitors</h2><span class="small">Availability uses recorded checks · history is local</span></div><button class="secondary" onclick="load()">Refresh</button></div><div id="checks"></div></section></div></main><script>const box=document.querySelector('#checks'),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function load(){let r=await fetch('/api/checks'),items=await r.json();box.innerHTML=items.length?items.map(c=>`<article class="card"><div class="row"><div><span class="pill ${c.last_ok===1?'up':c.last_ok===0?'down':''}">${c.last_ok==null?'WAITING':c.last_ok?'UP':'DOWN'}</span><h3>${esc(c.url)}</h3><div class="sub">Every ${c.interval_seconds}s · timeout ${c.timeout}s · ${c.last_status??'—'} · ${c.last_latency??'—'} ms · ${c.enabled?'enabled':'paused'}</div></div><div><button class="secondary" onclick="history(${c.id})">History</button> <button onclick="run(${c.id})">Check now</button> <button class="secondary" onclick="toggle(${c.id},${c.enabled?0:1})">${c.enabled?'Pause':'Resume'}</button></div></div><div id="h-${c.id}" class="history"></div></article>`).join(''):'<div class="empty">No checks configured. Add an explicit public service URL to get started.</div>'}async function run(id){await fetch('/api/checks/'+id+'/run',{method:'POST'});load()}async function toggle(id,enabled){await fetch('/api/checks/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled})});load()}async function history(id){let r=await fetch('/api/checks/'+id+'/history'),rows=await r.json();document.querySelector('#h-'+id).textContent=rows.length?rows.map(x=>`${new Date(x.checked_at).toLocaleString()} · ${x.ok?'UP':'DOWN'} · ${x.status_code??'no response'} · ${x.latency_ms??'—'} ms${x.error?' · '+x.error:''}`).join(' | '):'No results recorded yet.'}document.querySelector('#form').onsubmit=async e=>{e.preventDefault();let r=await fetch('/api/checks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(e.target)))}),d=await r.json();document.querySelector('#msg').textContent=r.ok?'Monitor added.':d.error;if(r.ok){e.target.reset();load()}};load();</script></body></html>'''
class Handler(BaseHTTPRequestHandler):
    def respond(self,code,data,ctype='application/json; charset=utf-8'):
        b=data.encode() if isinstance(data,str) else json.dumps(data).encode(); self.send_response(code); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(b))); self.send_header('X-Content-Type-Options','nosniff'); self.end_headers(); self.wfile.write(b)
    def body(self): return json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
    def do_GET(self):
        p=urlsplit(self.path).path
        if p=='/': return self.respond(200,PAGE,'text/html; charset=utf-8')
        if p=='/api/checks': return self.respond(200,list_checks())
        parts=p.strip('/').split('/')
        if len(parts)==4 and parts[:2]==['api','checks'] and parts[3]=='history':
            try:return self.respond(200,get_history(int(parts[2])))
            except (ValueError,KeyError) as e:return self.respond(400,{'error':str(e)})
        return self.respond(404,{'error':'Not found'})
    def do_POST(self):
        p=urlsplit(self.path).path
        try:
            if p=='/api/checks': return self.respond(201,create_check(self.body()))
            parts=p.strip('/').split('/')
            if len(parts)==4 and parts[:2]==['api','checks'] and parts[3]=='run': return self.respond(200,run_check(int(parts[2])))
            return self.respond(404,{'error':'Not found'})
        except (ValueError,KeyError,TypeError,json.JSONDecodeError) as e:return self.respond(400,{'error':str(e)})
    def do_PATCH(self):
        parts=urlsplit(self.path).path.strip('/').split('/')
        if len(parts)!=3 or parts[:2]!=['api','checks']: return self.respond(404,{'error':'Not found'})
        try:
            data=self.body(); enabled=data.get('enabled')
            if enabled not in (True,False,0,1): raise ValueError('enabled must be true or false.')
            set_enabled(int(parts[2]),enabled)
            return self.respond(200,{'enabled':bool(enabled)})
        except (ValueError,KeyError,TypeError,json.JSONDecodeError) as e: return self.respond(400,{'error':str(e)})
    def log_message(self,*args):pass

def main():
    initialize(); stop=threading.Event(); threading.Thread(target=monitor_loop,args=(stop,),daemon=True).start(); server=ThreadingHTTPServer(('127.0.0.1',8001),Handler); print('Pulse running at http://127.0.0.1:8001 (Ctrl+C to stop)'); server.serve_forever()
if __name__=='__main__':main()
