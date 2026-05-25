#!/usr/bin/env python3
"""
XDU 课表 API — 基于 XDYou (traintime_pda) 逆向的 ehall 服务
支持自动滑块验证码破解 + CAS 登录 + Cookie 持久化
"""
import json, os, re, datetime, random, string, base64, struct, urllib.parse
from typing import Optional, List, Dict, Any, Tuple
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ─── 配置 ────────────────────────────────────────
EHAIL_BASE = "https://ehall.xidian.edu.cn"
IDS_BASE = "https://ids.xidian.edu.cn"
APP_ID = "4770397878132218"
COOKIE_FILE = os.environ.get("COOKIE_FILE", "/tmp/xdu-cookies.json")
CACHE_FILE = os.environ.get("COOKIE_FILE", "/data/cookies.json").replace("cookies.json", "schedule_data.json")
DEFAULT_SEMESTER = "2025-2026-2"
DEFAULT_XH = "25009290006"
DEFAULT_UN = "25009290006"
DEFAULT_PW = ""

# Chaoxing Cache & Cookie
CX_COOKIE_FILE = os.environ.get("CX_COOKIE_FILE", "/data/cookies_chaoxing.json")
CX_CACHE_FILE = os.environ.get("COOKIE_FILE", "/data/cookies.json").replace("cookies.json", "chaoxing_cache.json")
CX_API = "https://fycourse.fanya.chaoxing.com"
CX_NOTICE = "https://notice.chaoxing.com"

PERIOD_TIME = {1:"08:30",2:"09:15",3:"10:30",4:"11:15",
               5:"14:00",6:"14:45",7:"16:00",8:"16:45",
               9:"19:00",10:"19:45",11:"20:30",12:"21:15"}
DAY_NAMES = {1:"周一",2:"周二",3:"周三",4:"周四",5:"周五",6:"周六",7:"周日"}

HEADERS = {
    "Referer": "http://ehall.xidian.edu.cn/new/index_xd.html",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}

AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

# ─── 滑块验证码破解 ─────────────────────────────

class SliderCaptchaSolver:
    """
    XDYou 滑块验证码自动破解
    流程: openSliderCaptcha.htl → tagWidth → generateTracks → AES加密 → verifySliderCaptcha.htl
    """
    
    @staticmethod
    def random_str(n: int) -> str:
        return ''.join(random.choice(AES_CHARS) for _ in range(n))
    
    @staticmethod
    def extract_aes_key(image_data: bytes) -> bytes:
        """图片最后 16 字节是 AES 密钥"""
        return image_data[-16:]
    
    @staticmethod
    def aes_encrypt(plain_text: str, key_bytes: bytes) -> str:
        """
        XDYou 的 AES-CBC 加密
        IV = random 16 chars
        payload = nonce(64 chars) + plain_text
        """
        iv_str = SliderCaptchaSolver.random_str(16)
        nonce = SliderCaptchaSolver.random_str(64)
        plain = (nonce + plain_text).encode('utf-8')
        
        key = key_bytes
        iv = iv_str.encode('utf-8')
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(plain, AES.block_size))
        return base64.b64encode(encrypted).decode()
    
    @staticmethod
    def encrypt_payload(payload: str, piece_data: bytes) -> str:
        """加密轨迹数据 - 对应 XDYou 的 _encryptPayload"""
        key_bytes = piece_data[-16:]  # 最后16字节作为密钥
        return SliderCaptchaSolver.aes_encrypt(payload, key_bytes)
    
    @staticmethod
    def generate_tracks(target_x: int) -> List[Dict]:
        """
        生成模拟人类拖拽轨迹
        对应 XDYou 的 generateTracks(targetX)
        """
        tracks = []
        current_x = 0
        current_y = 0
        
        # 起始点
        tracks.append({"a": 0, "b": 0, "c": 0})
        
        while current_x < target_x:
            remaining = target_x - current_x
            step_x = random.randint(5, 9) if remaining > 20 else random.randint(1, 3)
            current_x += step_x
            if current_x > target_x:
                current_x = target_x
            
            if random.random() > 0.7:
                current_y += 1 if random.random() > 0.5 else -1
            
            step_time = 20 + random.randint(0, 5)
            tracks.append({"a": current_x, "b": current_y, "c": step_time})
            
            if current_x == target_x:
                break
        
        # 结束停留点
        tracks.append({"a": target_x, "b": current_y, "c": 20 + random.randint(0, 9)})
        return tracks
    
    @staticmethod
    async def solve_captcha(client: httpx.AsyncClient) -> bool:
        """
        自动破解滑块验证码
        1. 获取验证码图片
        2. 从 tagWidth 获取正确偏移量
        3. 生成轨迹
        4. AES 加密
        5. 提交验证
        """
        import time
        ts = int(time.time() * 1000)
        
        # 1. 获取验证码图片 (use client's cookies automatically)
        r = await client.get(
            f"{IDS_BASE}/authserver/common/openSliderCaptcha.htl",
            params={'_': ts},
        )
        data = r.json()
        big_img = base64.b64decode(data["bigImage"])
        small_img = base64.b64decode(data["smallImage"])
        
        # tagWidth 是正确偏移量
        tag_width = int(float(data.get("tagWidth", 0)))
        print(f"[captcha] tagWidth={tag_width}")
        
        # 2. 生成轨迹
        tracks = SliderCaptchaSolver.generate_tracks(tag_width)
        
        # 3. 加密 payload
        payload = json.dumps({
            "canvasLength": 280,
            "moveLength": tag_width,
            "tracks": tracks,
        }, separators=(',', ':'))
        
        sign = SliderCaptchaSolver.encrypt_payload(payload, small_img)
        
        # 4. 提交验证 (use client cookies automatically)
        verify_headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Origin": IDS_BASE,
            "X-Requested-With": "XMLHttpRequest",
        }
        r = await client.post(
            f"{IDS_BASE}/authserver/common/verifySliderCaptcha.htl",
            data=f"sign={urllib.parse.quote(sign, safe="")}",
            headers=verify_headers,
        )
        result = r.json()
        success = result.get("errorCode") == 1
        print(f"[captcha] verify result: {result}")
        return success

# ─── Cookie 管理 ─────────────────────────────────

def load_cookies() -> dict:
    try:
        return json.load(open(COOKIE_FILE)) if os.path.exists(COOKIE_FILE) else {}
    except: return {}

def save_cookies(cookies: dict):
    os.makedirs(os.path.dirname(COOKIE_FILE) or ".", exist_ok=True)
    json.dump(cookies, open(COOKIE_FILE, "w"))

def make_client() -> httpx.AsyncClient:
    cookies = load_cookies()
    jar = httpx.Cookies()
    for k, v in cookies.items():
        jar.set(k, v, domain="ehall.xidian.edu.cn", path="/")
    return httpx.AsyncClient(
        base_url=EHAIL_BASE, headers=HEADERS, cookies=jar,
        follow_redirects=True, timeout=30.0,
    )

# ─── 解析工具 ─────────────────────────────────────

def parse_weeks(bitstring: str) -> List[int]:
    return [i+1 for i, b in enumerate(bitstring) if b == "1"]

def compute_period_time(start: int, end: int) -> str:
    if start in PERIOD_TIME and end in PERIOD_TIME:
        em = int(PERIOD_TIME[end].split(":")[0]) * 60 + int(PERIOD_TIME[end].split(":")[1]) + 45
        return f"{PERIOD_TIME[start]}-{em//60:02d}:{em%60:02d}"
    return ""

def compute_current_week(term_start: str) -> int:
    try:
        start = datetime.datetime.strptime(term_start[:10], "%Y-%m-%d")
        days = (datetime.datetime.now() - start).days
        return max(1, (days // 7) + 1)
    except:
        return 1

# ─── 缓存读写 ─────────────────────────────────────

def load_cache() -> dict:
    f = CACHE_FILE if os.path.exists(CACHE_FILE) else None
    if not f and os.path.exists("/tmp/xdu-schedule-cache.json"):
        f = "/tmp/xdu-schedule-cache.json"
    if f and os.path.exists(f):
        try:
            return json.load(open(f))
        except:
            pass
    return {}

def save_cache(data: dict):
    path = CACHE_FILE
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    json.dump(data, open(path, "w"), ensure_ascii=False)

def load_cx_cache() -> dict:
    try:
        f = CX_CACHE_FILE if os.path.exists(CX_CACHE_FILE) else None
        if not f and os.path.exists("/tmp/xdu-chaoxing-cache.json"):
            f = "/tmp/xdu-chaoxing-cache.json"
        if f:
            return json.load(open(f))
    except: pass
    return {}

def save_cx_cache(data: dict):
    path = CX_CACHE_FILE
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    json.dump(data, open(path, "w"), ensure_ascii=False)

# ─── 超星 Cookie 管理 ───────────────────────────────

def load_cx_cookies() -> dict:
    try:
        return json.load(open(CX_COOKIE_FILE)) if os.path.exists(CX_COOKIE_FILE) else {}
    except: return {}

def save_cx_cookies(cookies: dict):
    os.makedirs(os.path.dirname(CX_COOKIE_FILE) or ".", exist_ok=True)
    json.dump(cookies, open(CX_COOKIE_FILE, "w"))

def make_cx_client() -> httpx.AsyncClient:
    cookies = load_cx_cookies()
    jar = httpx.Cookies()
    for k, v in cookies.items():
        jar.set(k, v, domain=".chaoxing.com", path="/")
    return httpx.AsyncClient(follow_redirects=True, timeout=15.0, cookies=jar)

async def fetch_chaoxing_data() -> dict:
    """从超星 API 抓取课程列表和考勤数据"""
    client = make_cx_client()
    
    # Step 1: Course list
    r = await client.get(
        "https://fycourse.fanya.chaoxing.com/courselist/study",
        headers={"Host": "fycourse.fanya.chaoxing.com"},
    )
    html = r.text
    
    courses = []
    pattern = r'<div class="myde_course_item[^"]*"[^>]*cid="([^"]*)"[^>]*cname="([^"]*)"[^>]*>'
    for m in re.finditer(pattern, html):
        courses.append({"courseId": m.group(1), "courseName": m.group(2)})
    
    link_pattern = r'<a[^>]*href="([^"]*)"[^>]*class="[^"]*myde_course_a[^"]*"[^>]*>'
    for m in re.finditer(link_pattern, html):
        href = m.group(1)
        params = dict(re.findall(r'([\w]+)=([^&]+)', href))
        name_match = re.search(r'cname="([^"]*)"', html[:m.start()][-200:])
        cname = name_match.group(1) if name_match else ""
        for c in courses:
            if c["courseName"] == cname:
                c.update(params)
    
    print(f"[chaoxing] Courses: {len(courses)}")
    
    # Step 2: Attendance & progress
    r2 = await client.get(
        "https://fycourse.fanya.chaoxing.com/courselist/studyCourseDatashow?v=1",
        headers={"Host": "fycourse.fanya.chaoxing.com"},
    )
    
    table_html = r2.text
    rows = re.findall(r'<tr[^>]*>\s*<td[^>]*>.*?</tr>', table_html, re.DOTALL)
    
    attendance = []
    for tr in rows:
        cells = re.findall(r'<td[^>]*>(.*?)</td>', tr, re.DOTALL)
        clean = [re.sub(r'<[^>]+>', '', c).strip() for c in cells]
        if len(clean) >= 15:
            attendance.append({
                "courseName": clean[0], "className": clean[1],
                "checkIn": clean[2], "personalLeave": clean[3],
                "sickLeave": clean[4], "officialLeave": clean[5],
                "absence": clean[6], "requiredCheckIn": clean[7],
                "attendanceRate": clean[8], "readCount": clean[9],
                "unreadCount": clean[10], "accessCount": clean[11],
                "taskProgress": clean[12], "homeworkProgress": clean[13],
                "examProgress": clean[14], "discussionCount": clean[15],
                "materialCount": clean[16],
            })
    
    print(f"[chaoxing] Attendance: {len(attendance)}")
    await client.aclose()
    
    return {
        "courses": courses,
        "attendance": attendance,
        "updated": datetime.datetime.now().isoformat(),
    }

def extract_ehall_cookies(client: httpx.AsyncClient) -> dict:
    cookies = {}
    for c in client.cookies.jar:
        if "ehall" in str(c.domain or "") or "xidian" in str(c.domain or ""):
            cookies[c.name] = c.value
    return cookies

# ─── CAS 登录 ─────────────────────────────────────

async def cas_login(client: httpx.AsyncClient) -> bool:
    """
    通过 IDS CAS 登录 ehall，含自动滑块验证码破解
    """
    username = os.environ.get("XDU_USERNAME", DEFAULT_XH)
    password = os.environ.get("XDU_PASSWORD", DEFAULT_PW)
    if not password:
        print("[login] No password configured, can't auto-login")
        return False
    
    target = "https://ehall.xidian.edu.cn/login?service=https://ehall.xidian.edu.cn/new/index.html"
    
    try:
        # 1. 获取登录页面
        print("[login] Fetching login page...")
        r = await client.get(f"{IDS_BASE}/authserver/login", params={"service": target})
        page = r.text
        
        from html.parser import HTMLParser
        
        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.fields = {}
                self.in_form = False
            def handle_starttag(self, tag, attrs):
                d = dict(attrs)
                if tag == "input" and d.get("type") == "hidden" and d.get("name") and d.get("value"):
                    self.fields[d["name"]] = d["value"]
                if tag == "input" and d.get("id") == "pwdEncryptSalt" and d.get("value"):
                    self.fields["pwdEncryptSalt"] = d["value"]
        
        fp = FormParser()
        fp.feed(page)
        
        # 获取加密密钥
        keys = fp.fields.get("pwdEncryptSalt", "")
        print(f"[login] encrypt key: {keys}")
        
        # 2. AES 加密密码 (XDYou 的 aesEncrypt)
        prefix = "xidianscriptsxduxidianscriptsxduxidianscriptsxduxidianscriptsxdu"
        to_enc = (prefix + password).encode()
        
        # PKCS7 padding
        block_size = 16
        padding_len = block_size - len(to_enc) % block_size
        to_enc += bytes([padding_len] * padding_len)
        
        cipher = AES.new(keys.encode(), AES.MODE_CBC, iv=b'xidianscriptsxdu')
        pwd_enc = base64.b64encode(cipher.encrypt(to_enc)).decode()
        
        # 3. 获取验证码并自动破解
        print("[login] Solving captcha...")
        success = await SliderCaptchaSolver.solve_captcha(client)
        if not success:
            print("[login] Captcha solve failed")
            return False
        print("[login] Captcha solved!")
        
        # 4. 提交登录
        login_data = {
            'username': username,
            'password': pwd_enc,
            'rememberMe': 'true',
            'cllt': 'userNameLogin',
            'dllt': 'generalLogin',
            '_eventId': 'submit',
        }
        for key in ['lt', 'execution']:
            if key in fp.fields:
                login_data[key] = fp.fields[key]
        
        print("[login] Submitting login...")
        r = await client.post(
            f"{IDS_BASE}/authserver/login",
            params={"service": target},
            data=login_data,
            follow_redirects=False,
        )
        
        if r.status_code == 302:
            loc = r.headers.get("location", "")
            print(f"[login] Redirect: {loc}")
            # 跟随重定向
            await client.get(loc)
            
            # 保存 cookies
            save_cookies(extract_ehall_cookies(client))
            return True
        else:
            print(f"[login] Failed with status {r.status_code}")
            return False
            
    except Exception as e:
        print(f"[login] Error: {e}")
        return False

# ─── FastAPI ──────────────────────────────────────

app = FastAPI(title="XDU 课表 API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class CookieInput(BaseModel):
    cookies: Dict[str, str]

class LoginInput(BaseModel):
    username: str = DEFAULT_XH
    password: str = ""

@app.on_event("startup")
async def startup():
    save_cookies(load_cookies())

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "xdu-api"}

@app.get("/api/status")
async def status():
    async with make_client() as cl:
        try:
            r = await cl.get("/jsonp/getAppUsageMonitor.json?type=uv")
            d = r.json()
            has_login = d.get("hasLogin", False)
            save_cookies(extract_ehall_cookies(cl))
            return {"logged_in": has_login, "cookies_stored": len(load_cookies())}
        except:
            return {"logged_in": False, "error": "ehall 连接失败"}

@app.post("/api/cookies")
async def set_cookies(data: CookieInput):
    save_cookies(data.cookies)
    return {"status": "ok", "cookies_count": len(data.cookies)}

@app.post("/api/login")
async def login(data: LoginInput):
    """尝试自动 CAS 登录（含滑块验证码破解）"""
    os.environ["XDU_USERNAME"] = data.username
    if data.password:
        os.environ["XDU_PASSWORD"] = data.password
    
    async with make_client() as cl:
        ok = await cas_login(cl)
        if ok:
            return {"status": "ok", "message": "登录成功"}
        return {"status": "fail", "message": "登录失败，可能需要重新配置密码"}

class ImportInput(BaseModel):
    data: Dict[str, Any] = {}

@app.post("/api/import-schedule")
async def import_schedule(data: ImportInput):
    """从浏览器接收课表数据（绕过 CORS）"""
    d = data.data
    if "schedule" in d:
        ts = d.get("term_start", "2026-03-02")
        save_cache({"term_start": ts, "cached": d["schedule"]})
        return {"status": "ok", "count": len(d["schedule"])}
    return {"status": "fail", "message": "缺少schedule字段"}

# ─── 超星学习通 ─────────────────────────────────

@app.post("/api/chaoxing/import")
async def import_chaoxing(data: ImportInput):
    """从浏览器接收超星数据"""
    d = data.data
    if "courses" in d or "attendance" in d:
        save_cx_cache(d)
        return {"status": "ok", "courses": len(d.get("courses", [])), "attendance": len(d.get("attendance", []))}
    return {"status": "fail", "message": "缺少courses或attendance字段"}

@app.get("/api/chaoxing/courses")
async def chaoxing_courses():
    """课程列表及进度"""
    cx = load_cx_cache()
    return {
        "courses": cx.get("courses", []),
        "attendance": cx.get("attendance", []),
        "updated": cx.get("updated", ""),
    }

@app.get("/api/chaoxing/homework")
async def chaoxing_homework():
    """作业情况"""
    cx = load_cx_cache()
    return {"homework": cx.get("homework", []), "updated": cx.get("updated", "")}

@app.get("/api/chaoxing/inbox")
async def chaoxing_inbox():
    """收件箱消息"""
    cx = load_cx_cache()
    return {"messages": cx.get("messages", []), "count": len(cx.get("messages", [])), "updated": cx.get("updated", "")}

@app.get("/api/chaoxing/status")
async def chaoxing_status():
    """超星登录状态"""
    ck = load_cx_cookies()
    return {"cookies_stored": len(ck), "cookie_source": "chaoxing"}

class CxCookieInput(BaseModel):
    cookies: Dict[str, str]

@app.post("/api/chaoxing/cookies")
async def set_cx_cookies(data: CxCookieInput):
    """导入超星 Cookie"""
    save_cx_cookies(data.cookies)
    return {"status": "ok", "cookies_count": len(data.cookies)}

@app.post("/api/chaoxing/refresh")
async def refresh_chaoxing():
    """从超星 API 刷新缓存"""
    ck = load_cx_cookies()
    if not ck:
        return {"status": "fail", "message": "没有超星 Cookie，请先导入"}
    data = await fetch_chaoxing_data()
    save_cx_cache(data)
    return {
        "status": "ok",
        "courses": len(data["courses"]),
        "attendance": len(data["attendance"]),
        "updated": data["updated"],
    }

# ─── ehall 课表 ──────────────────────────────────

@app.get("/api/schedule")
async def get_schedule(semester: str = DEFAULT_SEMESTER, xh: str = DEFAULT_XH):
    async with make_client() as cl:
        # 1. Check login
        has_login = False
        try:
            r = await cl.get("/jsonp/getAppUsageMonitor.json?type=uv")
            has_login = r.json().get("hasLogin", False)
        except:
            pass
        
        # 2. If not logged in, try appShow to init session  
        if not has_login:
            try:
                await cl.get(f"/appShow?appId={APP_ID}", follow_redirects=True)
                save_cookies(extract_ehall_cookies(cl))
            except:
                pass

        # 3. Get term start
        xn = semester.split("-")[0]
        term_start = "2025-09-01"
        try:
            r = await cl.post("/jwapp/sys/wdkb/modules/jshkcb/cxjcs.do", 
                           data={"XN": f"{xn}-{semester.split('-')[1]}", "XQ": semester.split("-")[2]})
            term_start = r.json()["datas"]["cxjcs"]["rows"][0]["XQKSRQ"][:10]
        except:
            pass

        # 4. Get schedule (try live, fall back to cache)
        rows = []
        from_cache = False
        try:
            r = await cl.post("/jwapp/sys/wdkb/modules/xskcb/xskcb.do",
                           data={"XNXQDM": semester, "XH": xh})
            data = r.json()
            ext = data.get("datas", {}).get("xskcb", {}).get("extParams", {})
            if ext.get("code") == 1:
                rows = data["datas"]["xskcb"]["rows"]
            else:
                raise Exception(ext.get("msg", "API error"))
        except Exception as e:
            cache = load_cache()
            if "cached" in cache:
                rows = cache["cached"]
                term_start = cache.get("term_start", term_start)
                from_cache = True
                print(f"[schedule] Using cache ({len(rows)} entries)")
            else:
                raise HTTPException(502, f"获取课表失败: {str(e)}")

        # 5. Parse schedule (supports both ehall format and cached format)
        schedule = []
        for item in rows:
            # Check format type
            if "KSJC" in item:  # ehall raw format
                start_p = int(item.get("KSJC", 0))
                end_p = int(item.get("JSJC", 0))
                day = int(item.get("SKXQ", 0))
                weeks = parse_weeks(item.get("SKZC", ""))
                name = item.get("KCM", "")
                code = item.get("KCH", "")
                room = item.get("JASMC", "")
                teacher = item.get("SKJS", "")
            else:  # enhanced cached format
                start_p = int(item.get("periodStart", 0))
                end_p = int(item.get("periodEnd", 0))
                day = int(item.get("day", 0))
                weeks = item.get("weeks", [])
                name = item.get("name", "")
                code = item.get("code", "")
                room = item.get("room", "")
                teacher = item.get("teacher", "")
            schedule.append({
                "name": name, "code": code,
                "day": day, "day_name": DAY_NAMES.get(day, ""),
                "period_start": start_p, "period_end": end_p,
                "periods": list(range(start_p, end_p+1)) if start_p and end_p else [],
                "time": compute_period_time(start_p, end_p),
                "weeks": weeks,
                "classroom": room,
                "teacher": teacher,
            })

        current_week = compute_current_week(term_start)
        
        # Cache live data (converted to enhanced format)
        if not from_cache:
            cache_rows = []
            for item in rows:
                start_p = int(item.get("KSJC", 0))
                end_p = int(item.get("JSJC", 0))
                cache_rows.append({
                    "name": item.get("KCM", ""), "code": item.get("KCH", ""),
                    "day": int(item.get("SKXQ", 0)),
                    "periodStart": start_p, "periodEnd": end_p,
                    "weeks": parse_weeks(item.get("SKZC", "")),
                    "room": item.get("JASMC", ""),
                    "teacher": item.get("SKJS", ""),
                })
            save_cache({"term_start": term_start, "cached": cache_rows})

        return {
            "semester": semester, "term_start": term_start,
            "current_week": current_week, "from_cache": from_cache,
            "schedule": schedule,
        }

@app.get("/api/today")
async def today(semester: str = DEFAULT_SEMESTER, xh: str = DEFAULT_XH):
    full = await get_schedule(semester, xh)
    today_dow = datetime.datetime.now().isoweekday()
    w = full["current_week"]
    filtered = [c for c in full["schedule"] if c["day"] == today_dow and w in c["weeks"]]
    full["schedule"] = filtered
    full["date"] = datetime.datetime.now().strftime("%Y-%m-%d")
    return full

@app.get("/api/tomorrow")
async def tomorrow(semester: str = DEFAULT_SEMESTER, xh: str = DEFAULT_XH):
    full = await get_schedule(semester, xh)
    tomorrow_dow = (datetime.datetime.now().isoweekday() % 7) + 1
    w = full["current_week"]
    if datetime.datetime.now().isoweekday() == 7:
        w += 1
    filtered = [c for c in full["schedule"] if c["day"] == tomorrow_dow and w in c["weeks"]]
    full["schedule"] = filtered
    full["date"] = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    full["day_name"] = DAY_NAMES.get(tomorrow_dow, "")
    full["current_week"] = w
    return full

@app.get("/api/week")
async def week(week: int, semester: str = DEFAULT_SEMESTER, xh: str = DEFAULT_XH):
    full = await get_schedule(semester, xh)
    full["schedule"] = [c for c in full["schedule"] if week in c["weeks"]]
    return full
