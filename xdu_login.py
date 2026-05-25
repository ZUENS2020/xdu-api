#!/usr/bin/python3
"""
xdu_login.py — XDU Playwright-based CAS login service
Tries automated login via physical slider drag.
If captcha fails, falls back to stored cookies.
"""
import os, sys, json, base64, time, random, io
sys.path.insert(0, '/tmp/pw-venv/lib/python3.14/site-packages')
from playwright.sync_api import sync_playwright
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PIL import Image
import httpx

# ─── Config ──────────────────────────────────────
CHROME = os.environ.get("CHROME_PATH", "/home/zuens2020/.cache/puppeteer/chrome/linux-148.0.7778.167/chrome-linux64/chrome")
BASE = "https://ids.xidian.edu.cn"
EHAIL = "https://ehall.xidian.edu.cn"
COOKIE_OUT = os.environ.get("COOKIE_PATH", "/tmp/xdu-cookies-ehall.json")
COOKIE_DOCKER = "/var/lib/docker/volumes/xdu-api_xdu-data/_data/cookies.json"
COOKIE_BACKUP = "/tmp/xdu-cookies-all-playwright.json"

USER = os.environ.get("XDU_USERNAME", "25009290006")
PASS = os.environ.get("XDU_PASSWORD", "")
CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"

# ─── Gap Detection ───────────────────────────────

def detect_gap(jpeg_bytes: bytes, tag_width: int = 93) -> int:
    """Find gap position in captcha bigImage using column variance analysis"""
    img = Image.open(io.BytesIO(jpeg_bytes)).convert('RGB')
    w, h = 590, 360
    img = img.resize((w, h))
    px = list(img.getdata())
    
    best_x, best_score = 0, float('inf')
    for x in range(w - tag_width):
        col = [sum(px[y * w + x]) for y in range(h)]
        avg = sum(col) / h
        var = sum((v - avg) ** 2 for v in col) / h
        if var < best_score:
            best_score, best_x = var, x
    return best_x

def encrypt_for_captcha(payload_json: str, safe_key: str) -> str:
    """AES-CBC encrypt: nonce(64) + payload, IV random(16)"""
    iv = ''.join(random.choice(CHARS) for _ in range(16))
    nonce = ''.join(random.choice(CHARS) for _ in range(64))
    plain = (nonce + payload_json).encode()
    cipher = AES.new(safe_key.encode(), AES.MODE_CBC, iv.encode())
    return base64.b64encode(cipher.encrypt(pad(plain, AES.block_size))).decode()

# ─── Main Login Flow ─────────────────────────────

def do_login() -> dict:
    """
    Full Playwright login flow:
    1. Load login page, fill form
    2. Load captcha via $.load()
    3. Get safeSecure key from plugin
    4. Fetch captcha images (httpx with browser cookies)
    5. Detect gap with Pillow
    6. Call verify via page's own jQuery
    7. If verify OK, submit form
    8. Save cookies
    Returns {'ok': bool, 'cookies': int, 'msg': str}
    """
    start = time.time()
    
    with sync_playwright() as pw:
        b = pw.chromium.launch(
            headless=True, executable_path=CHROME,
            args=["--no-sandbox", "--headless=new"]
        )
        ctx = b.new_context(viewport={"width": 1280, "height": 900})
        pg = ctx.new_page()
        
        try:
            # --- Step 1: Load login page ---
            target = f"{BASE}/authserver/login?service={EHAIL}/login?service={EHAIL}/new/index.html"
            pg.goto(target, wait_until="domcontentloaded")
            pg.wait_for_timeout(2000)
            
            # --- Step 2: Salt + encrypt password ---
            salt = pg.evaluate("() => document.getElementById('pwdEncryptSalt')?.value || ''")
            if not salt:
                return {"ok": False, "cookies": 0, "msg": "no encrypt salt found"}
            
            prefix = "xidianscriptsxdu" * 4
            pwd_enc = base64.b64encode(
                AES.new(salt.encode(), AES.MODE_CBC, iv=b'xidianscriptsxdu').encrypt(
                    pad((prefix + PASS).encode(), 16)
                )
            ).decode()
            
            # --- Step 3: Fill form ---
            pg.evaluate(f"""() => {{
                document.querySelector('input[name="username"]').value = '{USER}';
                document.querySelector('input[name="password"]').value = '{pwd_enc}';
            }}""")
            
            # --- Step 4: Load captcha via $.load() ---
            pg.evaluate("""async () => {
                await new Promise((resolve) => {
                    var div = document.getElementById('sliderCaptchaDiv');
                    window.jQuery(div).load(
                        '/authserver/common/toSliderCaptcha.htl',
                        function() { setTimeout(resolve, 1500); }
                    );
                });
            }""")
            pg.wait_for_timeout(6000)
            
            # --- Step 5: Get safeSecure key ---
            safe_key = pg.evaluate("""() => {
                var sd = document.getElementById('sliderDiv');
                if (!sd) return '';
                try {
                    var pd = window.jQuery(sd).data('lgb.SliderCaptcha');
                    if (pd && pd.options && pd.options.safeSecure)
                        return pd.options.safeSecure.value;
                } catch(e) {}
                return '';
            }""")
            
            if not safe_key:
                return {"ok": False, "cookies": 0, "msg": "safeSecure key not found"}
            
            # --- Step 6: Fetch captcha images via httpx (reuse browser cookies) ---
            bc = ctx.cookies()
            cap_resp = None
            with httpx.Client() as cl:
                for c in bc:
                    cl.cookies.set(c['name'], c['value'], domain=c.get('domain', ''))
                
                cap_resp = cl.get(
                    f"{BASE}/authserver/common/openSliderCaptcha.htl",
                    params={"_": int(time.time() * 1000)},
                    headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                        "Accept": "application/json, text/javascript, */*; q=0.01",
                        "Referer": f"{BASE}/authserver/login",
                    }
                ).json()
            
            big_img = base64.b64decode(cap_resp['bigImage'])
            tag_width = int(float(cap_resp.get('tagWidth', 93)))
            
            # --- Step 7: Detect gap ---
            gap_img = detect_gap(big_img, tag_width)  # in 590px coords
            canvas_width = 280
            gap_canvas = max(10, min(270, round(gap_img * canvas_width / 590)))
            
            # --- Step 8: Generate human-like tracks ---
            tracks = [{"a": 0, "b": 0, "c": 0}]
            pos = 0
            while pos < gap_canvas:
                remaining = gap_canvas - pos
                step = min(random.randint(2, 6), remaining)
                pos += step
                if pos > gap_canvas:
                    pos = gap_canvas
                tracks.append({
                    "a": pos,
                    "b": random.choice([0, 0, 0, 1, -1]),
                    "c": 18 + random.randint(0, 10)
                })
            tracks.append({"a": gap_canvas, "b": 0, "c": 25 + random.randint(0, 10)})
            
            payload = json.dumps({
                "canvasLength": canvas_width,
                "moveLength": gap_canvas,
                "tracks": tracks,
            }, separators=(',', ':'))
            
            sign = encrypt_for_captcha(payload, safe_key)
            
            # --- Step 9: Verify via page's jQuery ---
            result = pg.evaluate(f"""() => {{
                var r = null;
                window.jQuery.ajax('/authserver/common/verifySliderCaptcha.htl', {{
                    data: {{sign: '{sign}'}},
                    cache: false, dataType: 'json', type: 'POST', async: false,
                    success: function(k) {{ r = k; }},
                    error: function(xhr, s, e) {{ r = {{error: s}}; }}
                }});
                return JSON.stringify(r);
            }}""")
            
            vr = json.loads(result) if isinstance(result, str) else result
            
            if isinstance(vr, dict) and vr.get('errorCode') == 1 and vr.get('spliced') is True:
                # Captcha verified! Submit login form
                pg.evaluate("""() => {
                    var form = document.querySelector('.loginFromClass');
                    if (form) form.submit();
                }""")
                pg.wait_for_timeout(8000)
                
                # Save cookies
                cookies = ctx.cookies()
                ehall_c = {c['name']: c['value'] for c in cookies if 'ehall' in c.get('domain', '')}
                
                with open(COOKIE_OUT, 'w') as f:
                    json.dump(ehall_c, f)
                # Also write to Docker volume for container access
                try:
                    os.makedirs(os.path.dirname(COOKIE_DOCKER), exist_ok=True)
                    with open(COOKIE_DOCKER, 'w') as f:
                        json.dump(ehall_c, f)
                except Exception:
                    pass
                with open(COOKIE_BACKUP, 'w') as f:
                    json.dump({c['name']: c['value'] for c in cookies}, f)
                
                elapsed = time.time() - start
                return {"ok": True, "cookies": len(ehall_c), "msg": f"登录成功, {len(ehall_c)} cookies ({elapsed:.0f}s)"}
            else:
                return {"ok": False, "cookies": 0, "msg": f"验证码失败: {vr}"}
                
        except Exception as e:
            return {"ok": False, "cookies": 0, "msg": f"错误: {e}"}
        finally:
            b.close()

# ─── CLI Entry ───────────────────────────────────

if __name__ == "__main__":
    # Quick check cookies first
    if os.path.exists(COOKIE_OUT):
        try:
            ck = json.load(open(COOKIE_OUT))
            if ck:
                # Try them against ehall
                with httpx.Client() as cl:
                    for k, v in ck.items():
                        cl.cookies.set(k, v, domain="ehall.xidian.edu.cn")
                    r = cl.get(f"{EHAIL}/jsonp/getAppUsageMonitor.json?type=uv", 
                              follow_redirects=True, timeout=10)
                    if r.json().get('hasLogin'):
                        print(f"✅ 现有 cookies 有效 ({len(ck)}个)")
                        sys.exit(0)
                    print(f"ℹ️  现有 cookies 过期，尝试登录...")
        except: pass
    
    result = do_login()
    print(f"{'✅' if result['ok'] else '❌'} {result['msg']}")
    
    # Final status check
    if result['ok']:
        print(f"Cookies saved to: {COOKIE_OUT}")
    else:
        # Try with stored cookies anyway (they might still work for some services)
        sys.exit(1)
