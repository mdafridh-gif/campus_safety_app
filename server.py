"""Campus Safety API and local development server (Python standard library only)."""
from __future__ import annotations
import base64, hashlib, hmac, json, mimetypes, os, re, secrets, sqlite3, time, uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CAMPUS_DB", ROOT / "campus_safety.db"))
PORT = int(os.environ.get("PORT", "8000"))
SOS_PHONE = os.environ.get("SOS_PHONE", "8531996611")
STORAGE_PATH = Path(os.environ.get("CAMPUS_PRIVATE_STORAGE", ROOT / "private_evidence"))
SESSIONS: dict[str, dict] = {}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
DEMO_PASSWORD = "CampusSafe2026!"  # Replace these seed users with institutional SSO before deployment.

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def hash_password(password,salt=None):
    salt=salt or secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310_000); return salt.hex()+":"+digest.hex()
def verify_password(password,encoded):
    try:salt_hex,digest_hex=encoded.split(":",1); return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt_hex),310_000).hex(),digest_hex)
    except (ValueError,TypeError):return False
def public_user(r):
    register=r["register_number"] if "register_number" in r.keys() else r["student_id"]
    return {"id":r["id"],"name":r["name"],"role":r["role"],"student_id":register or "","register_number":register or "","department":r["department"] or "","phone":r["phone"] or "","year_of_study":r["year_of_study"] or ""}
def connect():
    c=sqlite3.connect(DB_PATH); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c
def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, client_request_id TEXT UNIQUE, user_id TEXT NOT NULL, student_name TEXT NOT NULL, student_id TEXT, department TEXT, phone TEXT, incident_type TEXT NOT NULL, status TEXT NOT NULL, latitude REAL, longitude REAL, accuracy REAL, location_name TEXT, description TEXT DEFAULT '', assigned_to TEXT, resolution_notes TEXT DEFAULT '', started_at TEXT NOT NULL, resolved_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS timeline(id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), actor_id TEXT, actor_name TEXT, event_type TEXT NOT NULL, description TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), type TEXT NOT NULL, filename TEXT NOT NULL, file_size INTEGER DEFAULT 0, duration REAL, upload_status TEXT NOT NULL DEFAULT 'queued', checksum TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY, incident_id TEXT REFERENCES incidents(id), recipient_id TEXT, title TEXT NOT NULL, message TEXT NOT NULL, notification_type TEXT NOT NULL, status TEXT NOT NULL, is_read INTEGER DEFAULT 0, sent_at TEXT NOT NULL, read_at TEXT);
        CREATE TABLE IF NOT EXISTS calls(id TEXT PRIMARY KEY, incident_id TEXT REFERENCES incidents(id), recipient_id TEXT, phone_number TEXT, call_status TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT, duration INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, incident_id TEXT REFERENCES incidents(id), admin_id TEXT, actor_name TEXT, action TEXT NOT NULL, notes TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_logs(id TEXT PRIMARY KEY, actor_id TEXT, incident_id TEXT, action TEXT NOT NULL, details TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS contacts(id TEXT PRIMARY KEY, name TEXT, department TEXT, phone TEXT, email TEXT, priority INTEGER, is_active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, email TEXT NOT NULL COLLATE NOCASE UNIQUE, password_hash TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student','administrator')), student_id TEXT UNIQUE, register_number TEXT UNIQUE, department TEXT, phone TEXT, year_of_study TEXT, status TEXT NOT NULL DEFAULT 'active', last_login_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        """)
        user_sql=c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()[0]
        if "security_officer" in user_sql or "super_admin" in user_sql:
            c.execute("ALTER TABLE users RENAME TO users_legacy")
            c.execute("CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT NOT NULL COLLATE NOCASE UNIQUE, password_hash TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('student','administrator')), student_id TEXT UNIQUE, register_number TEXT UNIQUE, department TEXT, phone TEXT, year_of_study TEXT, status TEXT NOT NULL DEFAULT 'active', last_login_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            oldcols={r["name"] for r in c.execute("PRAGMA table_info(users_legacy)")}; year_expr="year_of_study" if "year_of_study" in oldcols else "''"
            reg_expr="register_number" if "register_number" in oldcols else "student_id"
            c.execute(f"INSERT INTO users(id,email,password_hash,name,role,student_id,register_number,department,phone,year_of_study,status,last_login_at,created_at,updated_at) SELECT id,email,password_hash,name,role,student_id,{reg_expr},department,phone,{year_expr},status,last_login_at,created_at,updated_at FROM users_legacy WHERE role IN ('student','administrator')")
            c.execute("DROP TABLE users_legacy")
        usercols={r["name"] for r in c.execute("PRAGMA table_info(users)")}
        if "year_of_study" not in usercols:c.execute("ALTER TABLE users ADD COLUMN year_of_study TEXT")
        if "register_number" not in usercols:
            c.execute("ALTER TABLE users ADD COLUMN register_number TEXT"); c.execute("UPDATE users SET register_number=student_id WHERE register_number IS NULL")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_register_number_idx ON users(register_number)")
        for uid,email,name,role,sid,dept,phone,year in [("USR-3001","admin@campus.edu","Priya Nair","administrator","","Administration","+91 98765 40002","")]:
            c.execute("INSERT OR IGNORE INTO users(id,email,password_hash,name,role,student_id,register_number,department,phone,year_of_study,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(uid,email,hash_password(DEMO_PASSWORD),name,role,sid or None,sid or None,dept,phone,year,now(),now()))
        if c.execute("SELECT count(*) FROM contacts").fetchone()[0]==0:
            for i,(name,dept,phone,email) in enumerate([("Campus Security Control","Security",SOS_PHONE,"security@campus.edu"),("Medical Response","Health Centre","112","health@campus.edu"),("Fire & Facilities","Facilities","101","facilities@campus.edu")]):
                c.execute("INSERT INTO contacts VALUES(?,?,?,?,?,?,1)",(f'CON-{i+1}',name,dept,phone,email,i+1))
def rowdict(r): return dict(r) if r else None
def incident(c,iid):
    r=c.execute("SELECT * FROM incidents WHERE id=?",(iid,)).fetchone()
    if not r:return None
    d=rowdict(r); d["timeline"]=[rowdict(x) for x in c.execute("SELECT * FROM timeline WHERE incident_id=? ORDER BY created_at",(iid,))]; d["evidence"]=[rowdict(x) for x in c.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY created_at DESC",(iid,))]; d["calls"]=[rowdict(x) for x in c.execute("SELECT * FROM calls WHERE incident_id=? ORDER BY started_at DESC",(iid,))]; d["notifications"]=[rowdict(x) for x in c.execute("SELECT * FROM notifications WHERE incident_id=? ORDER BY sent_at DESC",(iid,))]; return d
def add_event(c,iid,actor,event,desc):
    t=now(); c.execute("INSERT INTO timeline VALUES(?,?,?,?,?,?,?)",(str(uuid.uuid4()),iid,actor.get("id"),actor.get("name"),event,desc,t)); c.execute("INSERT INTO audit_logs VALUES(?,?,?,?,?,?)",(str(uuid.uuid4()),actor.get("id"),iid,event,desc,t))

class Handler(BaseHTTPRequestHandler):
    server_version="CampusSafety/1.0"
    def log_message(self,fmt,*args): print("%s - %s"%(self.address_string(),fmt%args))
    def send_json(self,data,status=200):
        body=json.dumps(data,ensure_ascii=False).encode(); self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("Content-Security-Policy","default-src 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'"); self.end_headers(); self.wfile.write(body)
    def body(self):
        n=int(self.headers.get("Content-Length",0))
        if n>22_000_000: raise ValueError("Request body is too large.")
        return json.loads(self.rfile.read(n) or b"{}")
    def auth(self,roles=None):
        token=self.headers.get("Authorization","").removeprefix("Bearer "); s=SESSIONS.get(token)
        if not s or s["expires"]<time.time(): raise PermissionError("Please sign in again.")
        if roles and s["user"]["role"] not in roles: raise PermissionError("You do not have access to this action.")
        return s["user"]
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/api/health": return self.send_json({"ok":True,"service":"campus-safety","time":now()})
        if not path.startswith("/api/"): return self.static(path)
        try:
            u=self.auth(); q=parse_qs(urlparse(self.path).query)
            with connect() as c:
                if path=="/api/location/classroom-photo":
                    if u["role"]!="administrator":raise PermissionError("Administrator access required.")
                    photo=ROOT/"assests"/"classroom.jpeg"
                    if not photo.is_file():return self.send_json({"error":"Classroom photo is unavailable."},404)
                    data=photo.read_bytes(); self.send_response(200); self.send_header("Content-Type","image/jpeg"); self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","private, no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(data); return
                if path=="/api/me": return self.send_json({"user":u,"contacts":[rowdict(x) for x in c.execute("SELECT * FROM contacts WHERE is_active=1 ORDER BY priority")]})
                if path=="/api/incidents":
                    terms=[]; vals=[]
                    if u["role"]=="student": terms.append("user_id=?"); vals.append(u["id"])
                    for key,col in [("status","status"),("type","incident_type"),("student","student_name"),("officer","assigned_to")]:
                        v=q.get(key,[""])[0]
                        if v: terms.append(f"{col} LIKE ?" if key in ("student","officer") else f"{col}=?"); vals.append(f"%{v}%" if key in ("student","officer") else v)
                    w=(" WHERE "+" AND ".join(terms)) if terms else ""; rows=[rowdict(x) for x in c.execute("SELECT * FROM incidents"+w+" ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'acknowledged' THEN 1 WHEN 'responding' THEN 2 ELSE 3 END, started_at DESC",vals)]
                    for r in rows:r["timeline"]=[rowdict(x) for x in c.execute("SELECT * FROM timeline WHERE incident_id=? ORDER BY created_at DESC LIMIT 5",(r["id"],))]
                    return self.send_json({"incidents":rows})
                if path.startswith("/api/incidents/"):
                    parts=path.split("/"); iid=parts[3]; d=incident(c,iid)
                    if not d:return self.send_json({"error":"Incident not found"},404)
                    if u["role"]=="student" and d["user_id"]!=u["id"]: raise PermissionError("You do not have access to this incident.")
                    return self.send_json({"incident":d})
                if path=="/api/admin/dashboard":
                    if u["role"]=="student": raise PermissionError("Administrator access required.")
                    counts={r[0]:r[1] for r in c.execute("SELECT status,count(*) FROM incidents GROUP BY status")}; active=[rowdict(x) for x in c.execute("SELECT * FROM incidents WHERE status IN ('active','acknowledged','responding') ORDER BY started_at")]
                    today=datetime.now(timezone.utc).date().isoformat(); today_count=c.execute("SELECT count(*) FROM incidents WHERE substr(started_at,1,10)=?",(today,)).fetchone()[0]; resolved_today=c.execute("SELECT count(*) FROM incidents WHERE status='resolved' AND substr(resolved_at,1,10)=?",(today,)).fetchone()[0]
                    responded=c.execute("SELECT AVG((julianday(t.created_at)-julianday(i.started_at))*86400) FROM incidents i JOIN timeline t ON t.incident_id=i.id AND t.event_type='RESPONDING' WHERE i.status IN ('responding','resolved')").fetchone()[0]
                    resolution=c.execute("SELECT AVG((julianday(resolved_at)-julianday(started_at))*86400) FROM incidents WHERE resolved_at IS NOT NULL").fetchone()[0]
                    return self.send_json({"metrics":{"active":sum(counts.get(s,0) for s in ('active','acknowledged','responding')),"today":today_count,"awaiting":counts.get('active',0),"resolved":resolved_today,"total":sum(counts.values()),"cancelled":counts.get('cancelled',0),"resolved_total":counts.get('resolved',0),"avg_response_seconds":int(responded or 0),"avg_resolution_seconds":int(resolution or 0)},"active":active,"categories":[rowdict(x) for x in c.execute("SELECT incident_type name,count(*) value FROM incidents GROUP BY incident_type ORDER BY value DESC")],"locations":[rowdict(x) for x in c.execute("SELECT location_name name,count(*) value FROM incidents GROUP BY location_name ORDER BY value DESC LIMIT 6")]})
                if path=="/api/notifications": return self.send_json({"notifications":[rowdict(x) for x in c.execute("SELECT * FROM notifications WHERE recipient_id IS NULL OR recipient_id=? ORDER BY sent_at DESC LIMIT 50",(u["id"],))]})
                if path.startswith("/api/evidence/"):
                    eid=path.rsplit("/",1)[-1]; e=c.execute("SELECT e.*,i.user_id FROM evidence e JOIN incidents i ON i.id=e.incident_id WHERE e.id=?",(eid,)).fetchone()
                    if not e or e["upload_status"]!="uploaded":return self.send_json({"error":"Evidence file not found."},404)
                    if u["role"]=="student" and e["user_id"]!=u["id"]:raise PermissionError("You do not have access to this evidence.")
                    p=STORAGE_PATH/e["incident_id"]/e["type"]/eid
                    if not p.is_file():return self.send_json({"error":"Evidence file is unavailable."},404)
                    data=p.read_bytes(); self.send_response(200); self.send_header("Content-Type","application/octet-stream"); self.send_header("Content-Length",str(len(data))); self.send_header("Content-Disposition",f'attachment; filename="{e["filename"].replace(chr(34), "")}"'); self.send_header("Cache-Control","private, no-store"); self.send_header("X-Content-Type-Options","nosniff"); self.end_headers(); self.wfile.write(data); return
                if path=="/api/admin/reports":
                    if u["role"]=="student": raise PermissionError("Administrator access required.")
                    return self.send_json({"categories":[rowdict(x) for x in c.execute("SELECT incident_type name,count(*) value FROM incidents GROUP BY incident_type")],"locations":[rowdict(x) for x in c.execute("SELECT location_name name,count(*) value FROM incidents GROUP BY location_name")],"statuses":[rowdict(x) for x in c.execute("SELECT status name,count(*) value FROM incidents GROUP BY status")]})
                if path=="/api/admin/audit":
                    if u["role"]=="student":raise PermissionError("Administrator access required.")
                    return self.send_json({"events":[rowdict(x) for x in c.execute("SELECT a.*,i.student_name,i.display_id FROM audit_logs a LEFT JOIN incidents i ON i.id=a.incident_id ORDER BY a.created_at DESC LIMIT 200")]})
            return self.send_json({"error":"Not found"},404)
        except PermissionError as e:return self.send_json({"error":str(e)},403)
        except Exception as e: print("API error",repr(e)); return self.send_json({"error":"Request could not be completed."},400)
    def do_POST(self):
        path=urlparse(self.path).path
        try:
            data=self.body()
            if path=="/api/auth/login":
                attempts=[t for t in LOGIN_ATTEMPTS.get(self.client_address[0],[]) if time.time()-t<300]; LOGIN_ATTEMPTS[self.client_address[0]]=attempts
                if len(attempts)>=8:return self.send_json({"error":"Too many sign in attempts. Try again in a few minutes."},429)
                email=str(data.get("email","")).strip().lower(); password=str(data.get("password","")); expected_role=str(data.get("expected_role", ""))
                with connect() as c:
                    r=c.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE",(email,)).fetchone()
                    if not r or r["status"]!="active" or (expected_role and r["role"]!=expected_role) or not verify_password(password,r["password_hash"]):LOGIN_ATTEMPTS[self.client_address[0]].append(time.time()); return self.send_json({"error":"Email or password is incorrect for this sign-in."},401)
                    u=public_user(r); t=now(); c.execute("UPDATE users SET last_login_at=?,updated_at=? WHERE id=?",(t,t,u["id"])); c.execute("INSERT INTO audit_logs VALUES(?,?,?,?,?,?)",(str(uuid.uuid4()),u["id"],None,"LOGIN",f"{u['role']} signed in",t)); c.commit()
                LOGIN_ATTEMPTS.pop(self.client_address[0],None)
                token=secrets.token_urlsafe(32); SESSIONS[token]={"user":u,"expires":time.time()+8*3600}; return self.send_json({"token":token,"user":u})
            if path=="/api/auth/register":
                name=" ".join(str(data.get("name", "")).split()); register_number=str(data.get("register_number", "")).strip().upper(); department=str(data.get("department", "")).strip(); phone=str(data.get("phone", "")).strip(); year=str(data.get("year_of_study", "")).strip(); email=str(data.get("email", "")).strip().lower(); password=str(data.get("password", ""))
                valid_years={"1st Year","2nd Year","3rd Year","4th Year","5th Year","6th Year","Postgraduate","Other"}
                if not name or len(name)>120:return self.send_json({"error":"Enter your name (up to 120 characters)."},422)
                if not re.fullmatch(r"[A-Z0-9/-]{3,32}",register_number):return self.send_json({"error":"Enter a register number (3–32 letters, numbers, hyphens, or slashes)."},422)
                if not department or len(department)>120:return self.send_json({"error":"Enter your department (up to 120 characters)."},422)
                if not re.fullmatch(r"[+0-9() .-]{7,24}",phone):return self.send_json({"error":"Enter a valid phone number."},422)
                if year not in valid_years:return self.send_json({"error":"Select your year of study."},422)
                if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email):return self.send_json({"error":"Enter a valid email address."},422)
                if len(password)<8:return self.send_json({"error":"Password must be at least 8 characters."},422)
                t=now(); uid="USR-"+secrets.token_hex(6).upper(); student_id=register_number
                try:
                    with connect() as c:
                        c.execute("INSERT INTO users(id,email,password_hash,name,role,student_id,register_number,department,phone,year_of_study,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'active',?,?)",(uid,email,hash_password(password),name,"student",student_id,student_id,department,phone,year,t,t)); c.execute("INSERT INTO audit_logs VALUES(?,?,?,?,?,?)",(str(uuid.uuid4()),uid,None,"STUDENT_REGISTERED","Student account created",t)); c.commit()
                except sqlite3.IntegrityError:return self.send_json({"error":"An account already exists for this email or student ID."},409)
                return self.send_json({"ok":True,"message":"Student account created. Sign in with your email and password."},201)
            u=self.auth()
            if path=="/api/auth/logout":
                token=self.headers.get("Authorization","").removeprefix("Bearer "); t=now()
                with connect() as c:c.execute("INSERT INTO audit_logs VALUES(?,?,?,?,?,?)",(str(uuid.uuid4()),u["id"],None,"LOGOUT",f"{u['role']} signed out",t)); c.commit()
                SESSIONS.pop(token,None); return self.send_json({"ok":True})
            with connect() as c:
                if path=="/api/incidents":
                    if u["role"]!="student": raise PermissionError("Only a student account can activate a student SOS.")
                    request_id=str(data.get("client_request_id", ""))[:80]
                    previous=c.execute("SELECT id,user_id FROM incidents WHERE client_request_id=?",(request_id,)).fetchone() if request_id else None
                    if previous:
                        if previous["user_id"]!=u["id"]:raise PermissionError("This alert request belongs to another account.")
                        return self.send_json({"incident":incident(c,previous["id"]),"delivery":"confirmed","message":"Campus safety has received your alert."},200)
                    iid="INC-"+datetime.now().strftime("%Y%m%d")+"-"+secrets.token_hex(3).upper(); t=now(); kind=str(data.get("incident_type") or "SOS / Personal Safety")[:80]; desc=str(data.get("description", ""))[:1500]
                    c.execute("INSERT INTO incidents(id,client_request_id,user_id,student_name,student_id,department,phone,incident_type,status,latitude,longitude,accuracy,location_name,description,started_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(iid,request_id or None,u["id"],u["name"],u["student_id"],u["department"],u["phone"],kind,"active",data.get("latitude"),data.get("longitude"),data.get("accuracy"),str(data.get("location_name", "Location pending"))[:180],desc,t,t,t)); add_event(c,iid,u,"SOS_ACTIVATED","SOS activated by student."); add_event(c,iid,u,"INCIDENT_CREATED","Emergency incident recorded; awaiting security acknowledgement.")
                    for rec in (None,"USR-2001","USR-3001"):
                        c.execute("INSERT INTO notifications VALUES(?,?,?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),iid,rec,"Campus emergency",f"{kind} reported by {u['name']}. Location: {data.get('location_name') or 'Pending'}.","in_app","sent",0,t,None))
                    c.execute("INSERT INTO calls VALUES(?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),iid,None,SOS_PHONE,"initiated",t,None,0)); add_event(c,iid,u,"CALL_INITIATED",f"Configured emergency-call workflow initiated for {SOS_PHONE}.")
                    response=incident(c,iid); c.commit(); return self.send_json({"incident":response,"delivery":"confirmed","message":"Campus safety has received your alert."},201)
                if path.startswith("/api/incidents/"):
                    parts=path.split("/"); iid=parts[3]; action=parts[4] if len(parts)>4 else ""; r=c.execute("SELECT * FROM incidents WHERE id=?",(iid,)).fetchone()
                    if not r:return self.send_json({"error":"Incident not found"},404)
                    if u["role"]=="student" and r["user_id"]!=u["id"]: raise PermissionError("You do not have access to this incident.")
                    if u["role"]=="student" and action not in ("cancel","evidence","location"): raise PermissionError("Security access required.")
                    if action=="location":
                        if u["role"]!="student" or r["user_id"]!=u["id"]:raise PermissionError("Only the reporting student can share a location.")
                        try:lat=float(data["latitude"]); lon=float(data["longitude"]); accuracy=max(0,float(data.get("accuracy",0)))
                        except Exception:return self.send_json({"error":"Valid coordinates are required."},422)
                        if not (-90<=lat<=90 and -180<=lon<=180):return self.send_json({"error":"Coordinates are outside valid bounds."},422)
                        loc=str(data.get("location_name") or "Shared device location")[:180]; c.execute("UPDATE incidents SET latitude=?,longitude=?,accuracy=?,location_name=?,updated_at=? WHERE id=?",(lat,lon,accuracy,loc,now(),iid)); add_event(c,iid,u,"LOCATION_RECEIVED",f"Location shared by student (accuracy ±{round(accuracy)} m)."); response=incident(c,iid); c.commit(); return self.send_json({"incident":response})
                    if action=="acknowledge": status="acknowledged"; event="ACKNOWLEDGED"
                    elif action=="assign": status=r["status"]; assignee=str(data.get("responder") or data.get("officer") or u["name"])[:120]; c.execute("UPDATE incidents SET assigned_to=?,updated_at=? WHERE id=?",(assignee,now(),iid)); event="RESPONDER_ASSIGNED"; desc=f"Incident assigned to responder {assignee}."
                    elif action=="respond": status="responding"; event="RESPONDING"
                    elif action=="arrive": status="responding"; event="OFFICER_ARRIVED"
                    elif action=="resolve":
                        if not str(data.get("notes", "")).strip():return self.send_json({"error":"Resolution notes are required."},422)
                        status="resolved"; event="RESOLVED"; c.execute("UPDATE incidents SET resolved_at=? WHERE id=?",(now(),iid))
                    elif action=="cancel":
                        if r["status"] not in ("active","acknowledged"): return self.send_json({"error":"This incident can no longer be cancelled."},409)
                        status="cancelled"; event="CANCELLED"
                    elif action=="status":
                        status=str(data.get("status", "")); allowed={"acknowledged":"ACKNOWLEDGED","responding":"RESPONDING","resolved":"RESOLVED","cancelled":"CANCELLED"}
                        if status not in allowed: return self.send_json({"error":"Invalid status transition."},422)
                        event=allowed[status]
                    elif action=="evidence":
                        typ=str(data.get("type", "text")); name=Path(str(data.get("filename", "Student note"))).name[:180]; detail=str(data.get("description", ""))[:1500]; t=now(); supplied_id=str(data.get("evidence_id") or "");
                        if supplied_id and not re.fullmatch(r"EVD-[A-F0-9]{8}",supplied_id):return self.send_json({"error":"Invalid evidence ID."},422)
                        eid=supplied_id or "EVD-"+secrets.token_hex(4).upper(); payload=data.get("file_base64"); size=0; checksum=None; stored=str(data.get("upload_status", "metadata_only"))
                        if typ not in ("text","audio","photo","video"):return self.send_json({"error":"Unsupported evidence type."},422)
                        if supplied_id and not c.execute("SELECT id FROM evidence WHERE id=? AND incident_id=?",(eid,iid)).fetchone():return self.send_json({"error":"Evidence item not found for this incident."},404)
                        if payload:
                            if typ=="text":return self.send_json({"error":"Text notes do not accept a file."},422)
                            try:blob=base64.b64decode(str(payload),validate=True)
                            except Exception:return self.send_json({"error":"Evidence encoding is invalid."},422)
                            if not blob or len(blob)>15*1024*1024:return self.send_json({"error":"Evidence file must be under 15 MB."},413)
                            checksum=hashlib.sha256(blob).hexdigest(); size=len(blob); folder=STORAGE_PATH/iid/typ; folder.mkdir(parents=True,exist_ok=True); (folder/eid).write_bytes(blob); stored="uploaded"
                        if supplied_id:
                            if not payload and stored not in ("recording","uploading","failed","metadata_only"):return self.send_json({"error":"Invalid evidence status."},422)
                            c.execute("UPDATE evidence SET filename=?,file_size=CASE WHEN ?>0 THEN ? ELSE file_size END,duration=COALESCE(?,duration),upload_status=?,checksum=COALESCE(?,checksum) WHERE id=? AND incident_id=?",(name,size,size,data.get("duration"),stored,checksum,eid,iid))
                            event="EVIDENCE_UPLOADED" if payload else ("EVIDENCE_CAPTURE_STARTED" if stored=="recording" else "EVIDENCE_UPLOAD_STATUS")
                            description=f"{typ.title()} evidence {('uploaded' if payload else stored)}: {name}. {detail}".strip()
                        else:
                            if not payload and stored not in ("recording","uploading","failed","metadata_only"):return self.send_json({"error":"Invalid evidence status."},422)
                            c.execute("INSERT INTO evidence(id,incident_id,type,filename,file_size,duration,upload_status,checksum,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(eid,iid,typ,name,size,data.get("duration"),stored,checksum,t)); event="EVIDENCE_UPLOADED" if payload else ("EVIDENCE_CAPTURE_STARTED" if stored=="recording" else "EVIDENCE_METADATA"); description=f"{typ.title()} evidence {('uploaded' if payload else stored)}: {name}. {detail}".strip()
                        add_event(c,iid,u,event,description); response=incident(c,iid); c.commit(); return self.send_json({"incident":response,"evidence_id":eid},201 if not supplied_id else 200)
                    else:return self.send_json({"error":"Unknown incident action"},404)
                    note=str(data.get("notes", ""))[:1500]
                    c.execute("UPDATE incidents SET status=?,resolution_notes=CASE WHEN ?<>'' THEN ? ELSE resolution_notes END,updated_at=? WHERE id=?",(status,note,note,now(),iid)); add_event(c,iid,u,event,str(data.get("description") or note or f"Incident marked {status}.")[:1500]); c.execute("INSERT INTO actions VALUES(?,?,?,?,?,?,?)",(str(uuid.uuid4()),iid,u["id"],u["name"],event,note,now())); response=incident(c,iid); c.commit(); return self.send_json({"incident":response})
                if path=="/api/notifications/read":
                    c.execute("UPDATE notifications SET is_read=1,read_at=? WHERE id=? AND (recipient_id IS NULL OR recipient_id=?)",(now(),data.get("id"),u["id"])); return self.send_json({"ok":True})
            return self.send_json({"error":"Not found"},404)
        except PermissionError as e:return self.send_json({"error":str(e)},403)
        except Exception as e: print("API error",repr(e)); return self.send_json({"error":"Request could not be completed."},400)
    def static(self,path):
        allowed={"/":"index.html","/index.html":"index.html","/app.js":"app.js","/styles.css":"styles.css"}
        if path not in allowed:return self.send_json({"error":"Not found"},404)
        p=ROOT/allowed[path]; b=p.read_bytes(); self.send_response(200); self.send_header("Content-Type",mimetypes.guess_type(p.name)[0] or "application/octet-stream"); self.send_header("Content-Length",str(len(b))); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("Content-Security-Policy","default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'"); self.end_headers(); self.wfile.write(b)

if __name__=="__main__":
    init_db(); print(f"Campus Safety is running at http://localhost:{PORT}"); ThreadingHTTPServer(("127.0.0.1",PORT),Handler).serve_forever()
