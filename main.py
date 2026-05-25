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
EXAM_CACHE_FILE = os.environ.get("COOKIE_FILE", "/data/cookies.json").replace("cookies.json", "exam_cache.json")
SCORE_CACHE_FILE = os.environ.get("COOKIE_FILE", "/data/cookies.json").replace("cookies.json", "score_cache.json")
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

def load_exam_cache() -> dict:
    f = EXAM_CACHE_FILE if os.path.exists(EXAM_CACHE_FILE) else None
    if f:
        try: return json.load(open(f))
        except: pass
    return {}

def save_exam_cache(data: dict):
    path = EXAM_CACHE_FILE
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    json.dump(data, open(path, "w"), ensure_ascii=False)

def load_score_cache() -> dict:
    f = SCORE_CACHE_FILE if os.path.exists(SCORE_CACHE_FILE) else None
    if f:
        try: return json.load(open(f))
        except: pass
    return {}

def save_score_cache(data: dict):
    path = SCORE_CACHE_FILE
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
    """从超星抓取课程列表和考勤数据"""
    client = make_cx_client()
    
    # Step 1: Course list from the study dashboard page
    r = await client.get(
        "https://fycourse.fanya.chaoxing.com/courselist/study",
        headers={"Host": "fycourse.fanya.chaoxing.com"},
    )
    html = r.text
    
    # Parse course data from dashboard
    courses = {}
    for m in re.finditer(r'<div[^>]*class="myde_course_item[^"]*"[^>]*cid="([^"]*)"[^>]*cname="([^"]*)"[^>]*>', html):
        cid = m.group(1)
        if cid not in courses:
            courses[cid] = {"courseId": cid, "courseName": m.group(2)}
    
    # Enrich from study page (has teacher, clazzId, etc.)
    try:
        r2 = await client.get(
            "https://mooc1-1.chaoxing.com/visit/courses/study",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            timeout=10.0,
        )
        study_html = r2.text
        for m in re.finditer(r'<input[^>]*name="courseId"[^>]*value="(\d+)"[^>]*>.*?<input[^>]*name="classId"[^>]*value="(\d+)"[^>]*>', study_html, re.DOTALL):
            cid2, clz = m.group(1), m.group(2)
            if cid2 in courses:
                courses[cid2]["clazzId"] = clz
                courses[cid2]["cpi"] = "482265202"
        # Extract teacher names
        for m in re.finditer(r'courseId="(\d+)"[^>]*>.*?<p[^>]*title="([^"]+)"[^>]*>', study_html, re.DOTALL):
            cid3 = m.group(1)
            if cid3 in courses and not courses[cid3].get("teacher"):
                courses[cid3]["teacher"] = m.group(2)
    except Exception as e:
        print(f"[chaoxing] study page fetch error: {e}")
    
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
    通过 IDS CAS 登录 ehall（已禁用，滑块无法自动破解）
    请用 Mac Chrome 手动登录后导入 Cookie
    """
    print("[login] Auto-login disabled, use Mac to import cookies")
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
    """滑块验证码无法自动破解，此端点已禁用，请用 Mac 导入 Cookie"""
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
        raw = d.get("courses", [])
        count = len(raw) if isinstance(raw, (list, dict)) else 0
        return {"status": "ok", "courses": count, "attendance": len(d.get("attendance", []))}
    return {"status": "fail", "message": "缺少courses或attendance字段"}

@app.get("/api/chaoxing/courses")
async def chaoxing_courses():
    """课程列表及进度"""
    cx = load_cx_cache()
    raw = cx.get("courses", [])
    if isinstance(raw, dict):
        courses = list(raw.values())
    else:
        courses = raw
    return {
        "courses": courses,
        "attendance": cx.get("attendance", []),
        "updated": cx.get("updated", ""),
    }

@app.get("/api/chaoxing/course/{course_id}/detail")
async def chaoxing_course_detail(course_id: str):
    """课程信息（老师、班级、时间、简介）"""
    client = make_cx_client()
    try:
        cx = load_cx_cache()
        course_info = {}
        for c in (cx.get("courses", []) if isinstance(cx.get("courses"), list) else cx.get("courses", {}).values()):
            if isinstance(c, dict) and c.get("courseId") == course_id:
                course_info = c
                break
        
        clazz_id = course_info.get("clazzId", "")
        
        result = {
            "courseId": course_id,
            "name": course_info.get("courseName", course_info.get("name", "")),
            "teacher": course_info.get("teacher", ""),
            "clazzId": clazz_id,
            "clazzName": course_info.get("courseName", ""),
        }
        
        # Try to get more detail from the course middle page
        if clazz_id:
            try:
                r = await client.get(
                    f"https://mooc1-1.chaoxing.com/visit/stucoursemiddle?courseid={course_id}&clazzid={clazz_id}&vc=1&cpi=482265202",
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                    timeout=8.0,
                )
                html = r.text
                if html and "温馨提示" not in html:
                    # Extract course metadata
                    match = re.search(r'<title>(.*?)</title>', html)
                    if match: result["name"] = match.group(1).replace("-首页", "")
                    # Extract chapter count
                    chapter_ids = set(re.findall(r'chapterId=(\d+)', html))
                    chapter_count = len(chapter_ids)
                    result["chapters"] = chapter_count
                    if chapter_count > 0:
                        result["hasContent"] = True
            except Exception as e:
                print(f"[chaoxing] detail fetch error: {e}")
        
        # If no chapters found, explicitly mark no content
        if "hasContent" not in result:
            result["hasContent"] = False
            if "chapters" not in result:
                result["chapters"] = 0
        
        # Also get progress info from attendance data
        for att in cx.get("attendance", []):
            if isinstance(att, dict) and att.get("courseName", "") == result["name"]:
                result["progress"] = {
                    "task": att.get("taskProgress", ""),
                    "homework": att.get("homeworkProgress", ""),
                    "exam": att.get("examProgress", ""),
                    "accessCount": att.get("accessCount", ""),
                }
                break
        
        return result
    finally:
        await client.aclose()


@app.get("/api/chaoxing/course/{course_id}/chapters")
async def chaoxing_course_chapters(course_id: str):
    """课程章节列表"""
    client = make_cx_client()
    try:
        cx = load_cx_cache()
        course_info = {}
        for c in (cx.get("courses", []) if isinstance(cx.get("courses"), list) else cx.get("courses", {}).values()):
            if isinstance(c, dict) and c.get("courseId") == course_id:
                course_info = c
                break

        clazz_id = course_info.get("clazzId", "")
        chapters = []

        if clazz_id:
            try:
                r = await client.get(
                    f"https://mooc1-1.chaoxing.com/visit/stucoursemiddle?courseid={course_id}&clazzid={clazz_id}&vc=1&cpi=482265202",
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                    timeout=8.0,
                )
                html = r.text
                if html and "温馨提示" not in html:
                    for m in re.finditer(r'chapterId=(\d+)[^>]*aria-label="([^"]+)"', html):
                        chapters.append({"chapterId": m.group(1), "name": m.group(2)})
            except Exception as e:
                print(f"[chaoxing] chapters fetch error: {e}")

        return {"courseId": course_id, "name": course_info.get("courseName", ""), "chapters": chapters, "chapterCount": len(chapters)}
    finally:
        await client.aclose()

@app.get("/api/chaoxing/course/{course_id}/materials")
async def chaoxing_course_materials(course_id: str):
    """课程资料列表"""
    client = make_cx_client()
    try:
        cx = load_cx_cache()
        course_info = {}
        for c in (cx.get("courses", []) if isinstance(cx.get("courses"), list) else cx.get("courses", {}).values()):
            if isinstance(c, dict) and c.get("courseId") == course_id:
                course_info = c
                break
        
        clazz_id = course_info.get("clazzId", "")
        materials = []
        
        if clazz_id:
            # Try the course middle page for materials
            try:
                r = await client.get(
                    f"https://mooc1-1.chaoxing.com/visit/stucoursemiddle?courseid={course_id}&clazzid={clazz_id}&vc=1&cpi=482265202",
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                    timeout=10.0,
                )
                html = r.text
                if html and "温馨提示" not in html:
                    # Parse resources links
                    for m in re.finditer(r'<a[^>]*href="([^"]+)"[^>]*>\s*<img[^>]*src="[^"]*/(?:ppt|pdf|word|excel|zip|video|file)[^.]*\.(?:png|jpg)"[^>]*>\s*</a>\s*<p[^>]*>\s*<a[^>]*href="[^"]+"[^>]*>([^<]+)</a>', html, re.DOTALL):
                        url = m.group(1)
                        name = m.group(2).strip()
                        ext = url.split('.')[-1].split('?')[0].lower() if '.' in url else ''
                        if name and len(name) < 100:
                            materials.append({"name": name, "url": url, "type": ext.upper() if ext else "link"})
                    
                    if not materials:
                        # Fallback: find all links with file extensions
                        for m in re.finditer(r'href="([^"]*(?:\.(?:ppt|pptx|pdf|doc|docx|zip|rar|mp4|flv|avi|xls|xlsx))[^"]*)"[^>]*>([^<]{2,80})</a>', html, re.DOTALL):
                            url, name = m.group(1), m.group(2).strip()
                            url = url if url.startswith('http') else f"https://mooc1-1.chaoxing.com{url}" if url.startswith('/') else url
                            ext = url.split('.')[-1].split('?')[0].lower() if '.' in url else ''
                            materials.append({"name": name, "url": url, "type": ext.upper() if ext else "未知"})
            except Exception as e:
                print(f"[chaoxing] materials fetch error: {e}")
        
        return {
            "courseId": course_id,
            "name": course_info.get("courseName", course_info.get("name", "")),
            "materials": materials,
            "material_count": len(materials),
            "note": "课程资料可能需要从浏览器访问才能获取完整内容" if not materials else "",
        }
    finally:
        await client.aclose()

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

# ─── ehall 通用工具 ──────────────────────────────

async def use_ehall_app(app_id: str) -> httpx.AsyncClient:
    """初始化 ehall app 会话，返回已登录的 client"""
    cookies = load_cookies()
    jar = httpx.Cookies()
    for k, v in cookies.items():
        jar.set(k, v, domain="ehall.xidian.edu.cn", path="/")
    cl = httpx.AsyncClient(follow_redirects=True, timeout=15.0, cookies=jar,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Referer": "http://ehall.xidian.edu.cn/new/index_xd.html",
        })
    
    # appShow → 302 redirect → follow it to init session
    r = await cl.get(f"https://ehall.xidian.edu.cn/appShow?appId={app_id}",
                     follow_redirects=False)
    if r.status_code == 302:
        loc = r.headers.get("location", "")
        if loc:
            await cl.get(loc)
    return cl

# ─── 考试安排 ────────────────────────────────────

def merge_exam_result(exams, unarranged, semester):
    return {
        "semester": semester,
        "count": len(exams),
        "unarranged_count": len(unarranged),
        "exams": exams,
        "unarranged": unarranged,
        "updated": datetime.datetime.now().isoformat(),
    }

@app.get("/api/exams")
async def get_exams(semester: str = DEFAULT_SEMESTER, refresh: bool = False):
    """考试安排查询"""
    cache = load_exam_cache()
    cached = cache.get(semester)
    if cached and not refresh:
        age = (datetime.datetime.now() - datetime.datetime.fromisoformat(cached["updated"])).total_seconds()
        if age < 1800:
            return cached
    
    cl = await use_ehall_app("4768687067472349")
    try:
        r = await cl.post(
            "https://ehall.xidian.edu.cn/jwapp/sys/studentWdksapApp/modules/wdksap/wdksap.do",
            params={"XNXQDM": semester, "*order": "-KSRQ,-KSSJMS"}
        )
        data = r.json()
        rows = data.get("datas", {}).get("wdksap", {}).get("rows", [])
        exams = []
        for item in rows:
            exams.append({
                "name": item.get("KCM", ""),
                "type": item.get("KSMC", ""),
                "time": item.get("KSSJMS", ""),
                "date": item.get("KSRQ", "")[:10],
                "location": item.get("JASMC", ""),
                "seat": item.get("ZWH", ""),
                "credits": item.get("XF", ""),
                "teacher": item.get("ZJJSXM", ""),
            })
        
        unarranged = []
        try:
            r2 = await cl.post(
                "https://ehall.xidian.edu.cn/jwapp/sys/studentWdksapApp/modules/wdksap/cxyxkwapkwdkc.do",
                params={"XNXQDM": semester}
            )
            d2 = r2.json()
            unr = d2.get("datas", {}).get("cxyxkwapkwdkc", {}).get("rows", [])
            for item in unr:
                unarranged.append({"name": item.get("KCM", ""), "code": item.get("KCH", "")})
        except:
            pass
        
        result = merge_exam_result(exams, unarranged, semester)
        cache[semester] = result
        save_exam_cache(cache)
        return result
    finally:
        await cl.aclose()

# ─── 考试成绩 ────────────────────────────────────

def merge_score_result(scores, semester):
    total_credits = sum(float(s["credit"]) for s in scores if s["credit"] and s["gpa"])
    total_points  = sum(float(s["credit"]) * float(s["gpa"]) for s in scores if s["credit"] and s["gpa"])
    gpa = round(total_points / total_credits, 2) if total_credits > 0 else None
    semesters = {}
    for s in scores:
        sem = s["semester"]
        if sem not in semesters:
            semesters[sem] = {"count": 0, "credits": 0}
        semesters[sem]["count"] += 1
        if s["credit"]:
            semesters[sem]["credits"] += float(s["credit"])
    return {"total": len(scores), "gpa": gpa, "semesters": semesters, "scores": scores, "updated": datetime.datetime.now().isoformat()}

@app.get("/api/scores")
async def get_scores(semester: str = "", refresh: bool = False):
    """考试成绩查询"""
    cache = load_score_cache()
    cached = cache.get("all")
    if cached and not refresh:
        age = (datetime.datetime.now() - datetime.datetime.fromisoformat(cached["updated"])).total_seconds()
        if age < 3600:
            s_list = cached["scores"]
            if semester:
                s_list = [s for s in s_list if s["semester"] == semester]
            return merge_score_result(s_list, semester)
    
    cl = await use_ehall_app("4768574631264620")
    try:
        query_setting = {"name": "SFYX", "value": "1", "linkOpt": "and", "builder": "m_value_equal"}
        r = await cl.post(
            "https://ehall.xidian.edu.cn/jwapp/sys/cjcx/modules/cjcx/xscjcx.do",
            data={"*json": 1, "querySetting": json.dumps(query_setting), "*order": "+XNXQDM,KCH,KXH", "pageSize": 1000, "pageNumber": 1}
        )
        rows = r.json().get("datas", {}).get("xscjcx", {}).get("rows", [])
        all_scores = []
        for item in rows:
            all_scores.append({
                "name": item.get("XSKCM", ""), "score": item.get("ZCJ", ""), "credit": item.get("XF", ""),
                "gpa": item.get("XFJD", ""), "semester": item.get("XNXQDM", ""),
                "category": item.get("KCXZDM_DISPLAY", ""), "type": item.get("KCLBDM_DISPLAY", ""),
                "level": item.get("DJCJMC", ""), "is_pass": item.get("SFJG", "") == "1",
                "exam_type": item.get("KSLXDM_DISPLAY", ""), "retake": item.get("CXCKDM_DISPLAY", ""),
                "class_id": item.get("JXBID", ""),
            })
        all_result = merge_score_result(all_scores, "")
        cache["all"] = all_result
        save_score_cache(cache)
        if semester:
            all_scores = [s for s in all_scores if s["semester"] == semester]
        return merge_score_result(all_scores, semester)
    finally:
        await cl.aclose()
