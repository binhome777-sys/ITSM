"""
농정원 ITSM 서버 — Render.com 배포용
"""
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import sqlite3, os, secrets, json
from datetime import datetime
from typing import Optional

app = FastAPI(title="농정원 ITSM")
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DB = os.path.join(os.path.dirname(__file__), "itsm.db")
security = HTTPBasic()

# ─── 계정: 환경변수 우선, 없으면 DB 기본값 ───
ADMIN_ID   = os.getenv("ADMIN_ID",   "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "1q2w3e4r!@")

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id          TEXT PRIMARY KEY,
            name        TEXT,
            dept        TEXT,
            grade       TEXT,
            position    TEXT,
            ext         TEXT,
            password    TEXT,
            must_change INTEGER DEFAULT 0,
            role        TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS items (
            id          TEXT PRIMARY KEY,
            uid         TEXT,
            name        TEXT,
            dept        TEXT,
            grade       TEXT,
            position    TEXT,
            date        TEXT,
            type        TEXT,
            content     TEXT,
            status      TEXT DEFAULT '대기',
            reg_at      TEXT,
            updated_at  TEXT
        );
        CREATE TABLE IF NOT EXISTS history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id     TEXT,
            action      TEXT,
            author      TEXT,
            created_at  TEXT
        );
    """)
    # admin 계정 없으면 삽입
    existing = conn.execute("SELECT id FROM accounts WHERE id=?", (ADMIN_ID,)).fetchone()
    if not existing:
        conn.execute("INSERT INTO accounts VALUES (?,?,?,?,?,?,?,0,'admin')",
            (ADMIN_ID, "관리자", "정보화팀", "", "IT담당자", "", ADMIN_PASS))
    conn.commit()
    conn.close()

@app.on_event("startup")
def startup():
    init_db()

# ─── 인증 ───
def get_user(credentials: HTTPBasicCredentials = Depends(security)):
    conn = get_db()
    row = conn.execute("SELECT * FROM accounts WHERE id=?",
                       (credentials.username,)).fetchone()
    conn.close()
    if not row or not secrets.compare_digest(credentials.password, row["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="아이디 또는 비밀번호가 올바르지 않습니다.",
            headers={"WWW-Authenticate": "Basic"})
    return dict(row)

def admin_only(user=Depends(get_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="관리자 권한 필요")
    return user

# ─── 메인 화면 ───
@app.get("/", response_class=HTMLResponse)
def root():
    # 여러 경로 시도
    candidates = [
        os.path.join(os.path.dirname(__file__), "index.html"),
        os.path.join(os.getcwd(), "index.html"),
        "index.html",
    ]
    for path in candidates:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return f.read()
    # 파일 목록 디버그 출력
    cwd_files = os.listdir(os.getcwd())
    return f"<h2>index.html 파일을 찾을 수 없습니다.</h2><p>현재 폴더: {os.getcwd()}</p><p>파일 목록: {cwd_files}</p>"

# ─── 내 정보 ───
@app.get("/api/me")
def me(user=Depends(get_user)):
    return {k: user[k] for k in
            ("id","name","dept","grade","position","role","must_change")}

# ─── 비밀번호 변경 ───
@app.post("/api/change-password")
def change_password(data: dict, user=Depends(get_user)):
    new_pw = data.get("new_password","")
    if not new_pw or len(new_pw) < 8:
        raise HTTPException(status_code=400, detail="비밀번호는 8자 이상이어야 합니다.")
    conn = get_db()
    conn.execute("UPDATE accounts SET password=?, must_change=0 WHERE id=?",
                 (new_pw, user["id"]))
    conn.commit(); conn.close()
    return {"result": "ok"}

# ─── ITSM 목록 ───
@app.get("/api/items")
def get_items(user=Depends(get_user)):
    conn = get_db()
    if user["role"] == "admin":
        rows = conn.execute(
            "SELECT * FROM items ORDER BY reg_at DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM items WHERE uid=? ORDER BY reg_at DESC",
            (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/items/{item_id}")
def get_item(item_id: str, user=Depends(get_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not row:
        conn.close(); raise HTTPException(status_code=404, detail="없음")
    item = dict(row)
    if user["role"] != "admin" and item["uid"] != user["id"]:
        conn.close(); raise HTTPException(status_code=403, detail="권한 없음")
    hist = conn.execute(
        "SELECT * FROM history WHERE item_id=? ORDER BY created_at",
        (item_id,)).fetchall()
    conn.close()
    item["history"] = [dict(h) for h in hist]
    return item

@app.post("/api/items")
def create_item(data: dict, user=Depends(get_user)):
    if not data.get("content","").strip():
        raise HTTPException(status_code=400, detail="접수내용 필요")
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    item_id = f"ITSM-{datetime.now().year}-{str(count+1).zfill(4)}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    conn.execute("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
        item_id, user["id"], user["name"], user["dept"],
        user.get("grade",""), user.get("position",""),
        data.get("date", now[:10]),
        data.get("type","기타"),
        data.get("content",""),
        "대기", now, now
    ))
    conn.execute("INSERT INTO history (item_id,action,author,created_at) VALUES (?,?,?,?)",
        (item_id, "접수 등록", user["name"], now))
    conn.commit(); conn.close()
    return {"id": item_id, "result": "ok"}

@app.patch("/api/items/{item_id}")
def update_item(item_id: str, data: dict, user=Depends(get_user)):
    conn = get_db()
    row = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not row:
        conn.close(); raise HTTPException(status_code=404, detail="없음")
    item = dict(row)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # 일반 사용자: 대기 상태일 때 내용 수정만 가능
    if user["role"] != "admin":
        if item["uid"] != user["id"]:
            conn.close(); raise HTTPException(status_code=403, detail="권한 없음")
        if item["status"] != "대기":
            conn.close(); raise HTTPException(status_code=400, detail="처리대기 상태만 수정 가능")
        changes = []
        if "date" in data and data["date"] != item["date"]:
            changes.append(f"접수일자: {item['date']} → {data['date']}")
        if "type" in data and data["type"] != item["type"]:
            changes.append(f"접수유형: {item['type']} → {data['type']}")
        if "content" in data and data["content"] != item["content"]:
            changes.append("접수내용 수정")
        conn.execute(
            "UPDATE items SET date=?,type=?,content=?,updated_at=? WHERE id=?",
            (data.get("date", item["date"]),
             data.get("type", item["type"]),
             data.get("content", item["content"]),
             now, item_id))
        if changes:
            conn.execute("INSERT INTO history (item_id,action,author,created_at) VALUES (?,?,?,?)",
                (item_id, f"수정됨 — {', '.join(changes)}", user["name"], now))
    else:
        # 관리자: 상태 변경 + 코멘트
        new_status = data.get("status", item["status"])
        conn.execute("UPDATE items SET status=?,updated_at=? WHERE id=?",
                     (new_status, now, item_id))
        comment = data.get("comment","")
        if new_status != item["status"]:
            st_map = {"대기":"처리대기","처리중":"처리중","완료":"완료"}
            action = f"상태 변경: {st_map.get(item['status'],item['status'])} → {st_map.get(new_status,new_status)}"
            conn.execute("INSERT INTO history (item_id,action,author,created_at) VALUES (?,?,?,?)",
                (item_id, action, user["name"], now))
        if comment:
            conn.execute("INSERT INTO history (item_id,action,author,created_at) VALUES (?,?,?,?)",
                (item_id, comment, user["name"], now))
    conn.commit(); conn.close()
    return {"result": "ok"}

# ─── 통계 (관리자) ───
@app.get("/api/stats")
def stats(user=Depends(admin_only)):
    conn = get_db()
    total  = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    wait   = conn.execute("SELECT COUNT(*) FROM items WHERE status='대기'").fetchone()[0]
    prog   = conn.execute("SELECT COUNT(*) FROM items WHERE status='처리중'").fetchone()[0]
    done   = conn.execute("SELECT COUNT(*) FROM items WHERE status='완료'").fetchone()[0]
    by_type= conn.execute("SELECT type, COUNT(*) cnt FROM items GROUP BY type ORDER BY cnt DESC").fetchall()
    by_dept= conn.execute("SELECT dept, COUNT(*) cnt FROM items GROUP BY dept ORDER BY cnt DESC LIMIT 10").fetchall()
    by_grade=conn.execute("SELECT grade, COUNT(*) cnt FROM items GROUP BY grade ORDER BY cnt DESC").fetchall()
    recent = conn.execute("SELECT * FROM items ORDER BY reg_at DESC LIMIT 5").fetchall()
    conn.close()
    return {"total":total,"wait":wait,"progress":prog,"done":done,
            "by_type":[dict(r) for r in by_type],
            "by_dept":[dict(r) for r in by_dept],
            "by_grade":[dict(r) for r in by_grade],
            "recent":[dict(r) for r in recent]}

# ─── 계정 관리 (관리자) ───
@app.get("/api/accounts")
def get_accounts(user=Depends(admin_only)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM accounts ORDER BY dept,name").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r); d.pop("password", None)
        result.append(d)
    return result

@app.post("/api/accounts")
def add_account(data: dict, user=Depends(admin_only)):
    uid = data.get("id","").strip()
    if not uid:
        raise HTTPException(status_code=400, detail="아이디 필요")
    import re
    if not re.match(r'^[a-zA-Z0-9._]+$', uid):
        raise HTTPException(status_code=400, detail="아이디는 영문·숫자·점만 사용 가능")
    conn = get_db()
    if conn.execute("SELECT id FROM accounts WHERE id=?", (uid,)).fetchone():
        conn.close(); raise HTTPException(status_code=400, detail="이미 존재하는 아이디")
    ext = data.get("ext","")
    digits = re.sub(r'[^0-9]', '', ext)
    pw = digits[-4:] if len(digits) >= 4 else "0000"
    conn.execute("INSERT INTO accounts VALUES (?,?,?,?,?,?,?,1,'user')", (
        uid, data.get("name",""), data.get("dept",""),
        data.get("grade",""), data.get("position",""), ext, pw))
    conn.commit(); conn.close()
    return {"result": "ok", "initial_password": pw}

@app.delete("/api/accounts/{uid}")
def del_account(uid: str, user=Depends(admin_only)):
    if uid == ADMIN_ID:
        raise HTTPException(status_code=400, detail="관리자 계정은 삭제 불가")
    conn = get_db()
    conn.execute("DELETE FROM accounts WHERE id=?", (uid,))
    conn.commit(); conn.close()
    return {"result": "ok"}

@app.post("/api/accounts/{uid}/reset-password")
def reset_password(uid: str, user=Depends(admin_only)):
    conn = get_db()
    row = conn.execute("SELECT ext FROM accounts WHERE id=?", (uid,)).fetchone()
    if not row:
        conn.close(); raise HTTPException(status_code=404, detail="계정 없음")
    import re
    digits = re.sub(r'[^0-9]', '', row["ext"] or "")
    pw = digits[-4:] if len(digits) >= 4 else "0000"
    conn.execute("UPDATE accounts SET password=?, must_change=1 WHERE id=?", (pw, uid))
    conn.commit(); conn.close()
    return {"result": "ok", "reset_password": pw}

# ─── 계정 일괄 초기화 (최초 1회) ───
@app.post("/api/seed-accounts")
def seed_accounts(data: dict, user=Depends(admin_only)):
    """관리자가 JSON으로 계정 목록을 일괄 등록"""
    accounts = data.get("accounts", [])
    conn = get_db()
    added = 0
    for a in accounts:
        existing = conn.execute("SELECT id FROM accounts WHERE id=?", (a["id"],)).fetchone()
        if not existing:
            conn.execute("INSERT INTO accounts VALUES (?,?,?,?,?,?,?,?,?)", (
                a["id"], a["name"], a["dept"], a["grade"],
                a["position"], a["ext"], a["password"],
                1 if a.get("mustChange") else 0,
                a.get("role","user")
            ))
            added += 1
    conn.commit(); conn.close()
    return {"result": "ok", "added": added}
