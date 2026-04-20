import ctypes
import importlib.util
import json
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import winreg


EMBEDDED_GETBALLS = r'''import gzip
import json
import threading
import time
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy

from mitmproxy import ctx, http


TARGET_HOST = "kf.qq.com"
TARGET_PATH = "/cgi-bin/commonNew"
TARGET_COMMAND = "F11129"

OUTPUT_FILE = "full_list.json"
DEBUG_RAW_FILE = "debug_page0_raw.txt"
DEBUG_JSON_FILE = "debug_page0_parsed.json"

CONCURRENCY = 8


def safe_json_loads(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None


def decode_url_json(s: str):
    if not s:
        return None
    try:
        return json.loads(urllib.parse.unquote(s))
    except Exception:
        return None


def parse_inner_command(command_value: str) -> dict:
    decoded = urllib.parse.unquote(command_value)
    qs = urllib.parse.parse_qs(decoded, keep_blank_values=True)
    return {k: v[0] for k, v in qs.items()}


def rebuild_inner_command(inner_params: dict) -> str:
    return urllib.parse.urlencode(inner_params, doseq=False)


def dedupe_rows(rows):
    seen = set()
    out = []
    for row in rows:
        key = json.dumps(row, ensure_ascii=False, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out


def extract_json_payload(text: str):
    candidates = []
    stripped = text.strip()
    if stripped:
        candidates.append(stripped)
        candidates.append(urllib.parse.unquote(stripped))
        candidates.append(urllib.parse.unquote_plus(stripped))

    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)

        obj = safe_json_loads(candidate)
        if obj is not None:
            return obj

        for left, right in (("{", "}"), ("[", "]")):
            l = candidate.find(left)
            r = candidate.rfind(right)
            if l != -1 and r != -1 and r > l:
                obj = safe_json_loads(candidate[l : r + 1])
                if obj is not None:
                    return obj

    return None


def normalize_resultinfo(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return extract_json_payload(value) or {}
    return {}


def dump_debug_files(raw_text: str, obj):
    try:
        with open(DEBUG_RAW_FILE, "w", encoding="utf-8") as f:
            f.write(raw_text)
    except Exception:
        pass

    try:
        with open(DEBUG_JSON_FILE, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def http_get_text(url: str, headers: dict, timeout: int = 20) -> str:
    """发起 HTTP GET 请求，自动处理 gzip/deflate 压缩，返回解码后的文本。"""
    req_headers = dict(headers)
    req_headers["Accept-Encoding"] = "gzip, deflate"

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers=req_headers, method="GET")
    with opener.open(request, timeout=timeout) as response:
        status = getattr(response, "status", response.getcode())
        if status >= 400:
            raise RuntimeError(f"HTTP {status}")

        content_encoding = response.headers.get("Content-Encoding", "").lower()
        raw_data = response.read()

        if content_encoding == "gzip" or raw_data[:2] == b"\x1f\x8b":
            try:
                raw_data = gzip.decompress(raw_data)
            except Exception:
                pass
        elif content_encoding == "deflate":
            try:
                raw_data = zlib.decompress(raw_data)
            except Exception:
                try:
                    raw_data = zlib.decompress(raw_data, -zlib.MAX_WBITS)
                except Exception:
                    pass

        try:
            return raw_data.decode("utf-8")
        except UnicodeDecodeError:
            return raw_data.decode("latin-1")


class FullFetcher:
    def __init__(self):
        self.running = False
        self.finished = False

    def log(self, msg: str):
        ctx.log.info(msg)

    def configure(self, updated):
        # 压制 mitmproxy 连接层日志（client connect / server connect 等）
        try:
            import logging
            logging.getLogger("mitmproxy.proxy").setLevel(logging.ERROR)
            logging.getLogger("mitmproxy.server").setLevel(logging.ERROR)
        except Exception:
            pass

    def request(self, flow: http.HTTPFlow):
        if flow.request.host != TARGET_HOST:
            flow.response = http.Response.make(403, b"")
            return

    def match_target(self, flow: http.HTTPFlow):
        req = flow.request
        if req.host != TARGET_HOST:
            return False

        path_only = req.path.split("?", 1)[0]
        if path_only != TARGET_PATH:
            return False

        outer_qs = urllib.parse.parse_qs(
            urllib.parse.urlparse(req.pretty_url).query,
            keep_blank_values=True,
        )
        command_outer = outer_qs.get("command", [""])[0]
        if not command_outer:
            return False

        inner = parse_inner_command(command_outer)
        return inner.get("command") == TARGET_COMMAND

    def response(self, flow: http.HTTPFlow):
        if self.running or self.finished:
            return

        if not self.match_target(flow):
            return

        self.running = True
        threading.Thread(target=self.fetch_all_from_flow, args=(flow,), daemon=True).start()

    def _build_url(self, parsed, outer_params, base_inner, page_idx):
        """构造指定页码的完整 URL。"""
        current_inner = deepcopy(base_inner)
        current_inner["pageindex"] = str(page_idx)

        current_outer = deepcopy(outer_params)
        current_outer["command"] = rebuild_inner_command(current_inner)
        if "t" in current_outer:
            current_outer["t"] = str(int(time.time() * 1000))

        return urllib.parse.urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                urllib.parse.urlencode(current_outer),
                parsed.fragment,
            )
        )

    def _fetch_one_page(self, url, headers, page_num):
        """拉取单页，返回 (page_num, page_rows, has_next_page) 或失败信息。"""
        max_retries = 3
        for retry in range(max_retries):
            try:
                text = http_get_text(url, headers=headers, timeout=20).strip()
                obj = extract_json_payload(text)
                if obj is None:
                    l, r = text.find("{"), text.rfind("}")
                    if l != -1 and r != -1 and r > l:
                        obj = safe_json_loads(text[l : r + 1])
                if obj:
                    break
                if retry < max_retries - 1:
                    time.sleep(0.5)
            except Exception:
                if retry < max_retries - 1:
                    time.sleep(0.5)

        if not obj:
            return page_num, None, False

        resultinfo = normalize_resultinfo(obj.get("resultinfo", {}))
        entries = resultinfo.get("list", [])

        page_rows = []
        has_next_page = False
        th = None

        for entry in entries:
            data = decode_url_json(entry.get("data", ""))
            th_entry = decode_url_json(entry.get("table_head", ""))
            if isinstance(data, list):
                page_rows.extend(data)
            if th_entry and th is None:
                th = th_entry
            if str(entry.get("has_next_page", "0")) == "1":
                has_next_page = True

        return page_num, page_rows, has_next_page, th

    def fetch_all_from_flow(self, flow: http.HTTPFlow):
        try:
            req = flow.request
            parsed = urllib.parse.urlparse(req.pretty_url)
            outer_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            outer_params = {k: v[0] for k, v in outer_qs.items()}

            command_outer = outer_params.get("command", "")
            inner_params = parse_inner_command(command_outer)

            self.log("正在获取道具流水...")

            base_inner = deepcopy(inner_params)
            start_page = int(base_inner.get("pageindex", "0"))

            headers = dict(req.headers)
            headers.pop("Content-Length", None)
            headers.pop("Transfer-Encoding", None)
            headers.pop("Host", None)
            headers.pop("Connection", None)

            all_rows = []
            table_head = None
            next_page = start_page
            empty_streak = 0
            dup_streak = 0
            max_pages = 2000
            fetched = 0

            with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
                while fetched < max_pages:
                    # 计算本批要拉取的页码
                    batch_size = min(CONCURRENCY, max_pages - fetched)
                    batch_pages = list(range(next_page, next_page + batch_size))

                    # 构造 URL 并提交
                    futures = {}
                    for p in batch_pages:
                        url = self._build_url(parsed, outer_params, base_inner, p)
                        futures[pool.submit(self._fetch_one_page, url, headers, p)] = p

                    # 收集结果
                    batch_results = []
                    for future in as_completed(futures):
                        result = future.result()
                        batch_results.append(result)

                    # 按页码排序处理
                    batch_results.sort(key=lambda r: r[0])

                    any_empty = False
                    any_dup = False
                    for result in batch_results:
                        page_num = result[0]
                        page_rows = result[1]
                        has_next = result[2]
                        th = result[3] if len(result) > 3 else None

                        if page_rows is None:
                            # 请求失败
                            any_empty = True
                            continue

                        if th and table_head is None:
                            table_head = th

                        before = len(all_rows)
                        all_rows.extend(page_rows)
                        all_rows = dedupe_rows(all_rows)
                        added = len(all_rows) - before

                        if fetched + batch_pages.index(page_num) < len(batch_pages):
                            pass  # 日志在下面统一输出

                        if not page_rows:
                            any_empty = True
                        if page_rows and added == 0:
                            any_dup = True

                        fetched += 1

                    # 日志：只显示本批中非空的最后一条
                    last_valid = None
                    for result in batch_results:
                        pn = result[0]
                        pr = result[1]
                        if pr is not None:
                            last_valid = (pn, len(all_rows))

                    if last_valid:
                        self.log(
                            f"page {fetched} 当前 {len(all_rows)}条"
                        )

                    next_page += batch_size

                    # 判断终止条件
                    all_empty = all(
                        (r[1] is None or len(r[1]) == 0) for r in batch_results
                    )
                    if all_empty:
                        empty_streak += 1
                    else:
                        empty_streak = 0

                    if any_empty and not any_dup:
                        dup_streak = 0
                    elif any_dup:
                        dup_streak += 1
                    else:
                        dup_streak = 0

                    if empty_streak >= 2:
                        self.log("[done] 连续 2 批为空，获取完成")
                        break

                    if dup_streak >= 2:
                        self.log("[done] 连续 2 批没有新增记录，获取完成")
                        break

            out = {
                "count": len(all_rows),
                "table_head": table_head,
                "rows": all_rows,
            }

            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)

            self.log(f"[saved] 已写入 {OUTPUT_FILE}")
            self.finished = True

        except Exception as e:
            self.log(f"[exception] {type(e).__name__}: {e}")
        finally:
            self.running = False


addons = [FullFetcher()]
'''


PROXY_SERVER = "127.0.0.1:8080"
PAC_SERVER = "127.0.0.1:8090"
PAC_PATH = "/proxy.pac"
TARGET_HOST = "kf.qq.com"
TARGET_PATH = "/cgi-bin/commonNew"
MITM_CHILD_FLAG = "--run-embedded-mitm"
VIEWER_HOST = "127.0.0.1"

INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


def module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def ensure_python_package(package_name: str, import_name: str | None = None):
    import_name = import_name or package_name
    if module_available(import_name):
        return

    if getattr(sys, "frozen", False):
        raise ModuleNotFoundError(
            f"missing bundled dependency: {package_name}. "
            "Please rebuild the executable with this package included."
        )

    print(f"[+] 缺少依赖 {package_name}，正在自动安装...")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            package_name,
        ],
        check=False,
    )
    if result.returncode != 0 or not module_available(import_name):
        raise RuntimeError(f"自动安装依赖失败: {package_name}")

    importlib.invalidate_caches()
    print(f"[+] 依赖安装完成: {package_name}")


def internet_set_option():
    fn = ctypes.windll.Wininet.InternetSetOptionW
    fn(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    fn(0, INTERNET_OPTION_REFRESH, 0, 0)


def read_proxy_state():
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ) as key:
        state = {}

        def read_value(name):
            try:
                value, regtype = winreg.QueryValueEx(key, name)
                return {"exists": True, "value": value, "type": regtype}
            except FileNotFoundError:
                return {"exists": False, "value": None, "type": None}

        for name in ["ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect"]:
            state[name] = read_value(name)
        return state


def write_reg_value(key, name, value, regtype):
    winreg.SetValueEx(key, name, 0, regtype, value)


def delete_reg_value_if_exists(key, name):
    try:
        winreg.DeleteValue(key, name)
    except FileNotFoundError:
        pass


def set_system_proxy_pac(pac_url: str):
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
        write_reg_value(key, "AutoDetect", 0, winreg.REG_DWORD)
        write_reg_value(key, "ProxyEnable", 0, winreg.REG_DWORD)
        delete_reg_value_if_exists(key, "ProxyServer")
        delete_reg_value_if_exists(key, "ProxyOverride")
        write_reg_value(key, "AutoConfigURL", pac_url, winreg.REG_SZ)
    internet_set_option()


def set_system_proxy_server(proxy_server: str):
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
        write_reg_value(key, "AutoDetect", 0, winreg.REG_DWORD)
        delete_reg_value_if_exists(key, "AutoConfigURL")
        write_reg_value(key, "ProxyEnable", 1, winreg.REG_DWORD)
        write_reg_value(key, "ProxyServer", proxy_server, winreg.REG_SZ)
        write_reg_value(key, "ProxyOverride", "<local>", winreg.REG_SZ)
    internet_set_option()


def fetch_url_without_proxy(url: str, timeout: int = 5) -> str:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def verify_system_proxy_pac(pac_url: str, retries: int = 10, delay: float = 0.5):
    last_error = None
    for _ in range(retries):
        try:
            state = read_proxy_state()
            auto_config_url = state["AutoConfigURL"]["value"] if state["AutoConfigURL"]["exists"] else None
            proxy_enable = int(state["ProxyEnable"]["value"]) if state["ProxyEnable"]["exists"] else 0
            auto_detect = int(state["AutoDetect"]["value"]) if state["AutoDetect"]["exists"] else 0

            if auto_config_url != pac_url:
                raise RuntimeError(f"AutoConfigURL 未生效: {auto_config_url!r}")
            if proxy_enable != 0:
                raise RuntimeError(f"ProxyEnable 应为 0，实际为 {proxy_enable}")
            if auto_detect != 0:
                raise RuntimeError(f"AutoDetect 应为 0，实际为 {auto_detect}")

            pac_text = fetch_url_without_proxy(pac_url, timeout=5)
            if TARGET_HOST not in pac_text or TARGET_PATH not in pac_text or PROXY_SERVER not in pac_text:
                raise RuntimeError("PAC 内容不匹配预期目标")
            return
        except Exception as exc:
            last_error = exc
            time.sleep(delay)

    raise RuntimeError(f"系统代理未确认生效: {last_error}")


def verify_system_proxy_server(proxy_server: str, retries: int = 10, delay: float = 0.5):
    last_error = None
    for _ in range(retries):
        try:
            state = read_proxy_state()
            auto_config_url = state["AutoConfigURL"]["value"] if state["AutoConfigURL"]["exists"] else None
            proxy_enable = int(state["ProxyEnable"]["value"]) if state["ProxyEnable"]["exists"] else 0
            current_proxy = state["ProxyServer"]["value"] if state["ProxyServer"]["exists"] else None

            if auto_config_url:
                raise RuntimeError(f"AutoConfigURL 应为空，实际为 {auto_config_url!r}")
            if proxy_enable != 1:
                raise RuntimeError(f"ProxyEnable 应为 1，实际为 {proxy_enable}")
            if current_proxy != proxy_server:
                raise RuntimeError(f"ProxyServer 未生效: {current_proxy!r}")
            return
        except Exception as exc:
            last_error = exc
            time.sleep(delay)

    raise RuntimeError(f"系统直连代理未确认生效: {last_error}")


def restore_proxy_state(state):
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
        for name, item in state.items():
            if item["exists"]:
                write_reg_value(key, name, item["value"], item["type"])
            else:
                delete_reg_value_if_exists(key, name)
    internet_set_option()


def wait_for_port(host: str, port: int, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((host, port))
            return True
        except Exception:
            time.sleep(0.5)
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


def make_pac_content(proxy_server: str):
    return f"""function FindProxyForURL(url, host) {{
    if (host === "{TARGET_HOST}" && shExpMatch(url, "*://{TARGET_HOST}{TARGET_PATH}*")) {{
        return "PROXY {proxy_server}";
    }}
    return "DIRECT";
}}
"""


class PacRequestHandler(BaseHTTPRequestHandler):
    pac_content = ""

    def do_GET(self):
        if self.path != PAC_PATH:
            self.send_error(404)
            return

        content = self.pac_content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format, *args):
        return


def start_pac_server(proxy_server: str):
    PacRequestHandler.pac_content = make_pac_content(proxy_server)
    host, port = PAC_SERVER.split(":")
    server = ThreadingHTTPServer((host, int(port)), PacRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def write_embedded_script(temp_dir: Path):
    local_script = Path.cwd() / "getballs.py"
    if local_script.exists():
        script_path = temp_dir / "getballs.py"
        script_path.write_text(local_script.read_text(encoding="utf-8"), encoding="utf-8")
        return script_path

    script_path = temp_dir / "getballs.py"
    script_path.write_text(EMBEDDED_GETBALLS, encoding="utf-8")
    return script_path


def bundle_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def resource_path(name: str) -> Path:
    return bundle_dir() / name


def current_entrypoint() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable)
    return Path(__file__).resolve()


def find_available_port(host: str) -> int:
    with socket.socket() as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def make_viewer_request_handler(work_dir: Path, viewer_file: Path):
    class ViewerRequestHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            path_only = urllib.parse.urlparse(self.path).path

            if path_only in ("/", "/viewer.html"):
                body = viewer_file.read_bytes()
                content_type = "text/html; charset=utf-8"
            elif path_only == "/full_list.json":
                json_file = work_dir / "full_list.json"
                if not json_file.exists():
                    self.send_error(404, "full_list.json not found")
                    return
                body = json_file.read_bytes()
                content_type = "application/json; charset=utf-8"
            else:
                self.send_error(404)
                return

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return ViewerRequestHandler


def start_viewer_server(work_dir: Path):
    viewer_file = resource_path("viewer.html")
    if not viewer_file.exists():
        raise FileNotFoundError(f"missing bundled viewer file: {viewer_file}")

    port = find_available_port(VIEWER_HOST)
    server = ThreadingHTTPServer(
        (VIEWER_HOST, port),
        make_viewer_request_handler(work_dir, viewer_file),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://{VIEWER_HOST}:{port}/viewer.html"


def open_viewer_page(url: str):
    def _open():
        try:
            webbrowser.open(url, new=1)
        except Exception as exc:
            print(f"[warn] failed to open browser automatically: {exc}")
            print(f"[hint] open this URL manually: {url}")

    threading.Thread(target=_open, daemon=True).start()


def run_embedded_mitm(script_path: Path):
    ensure_python_package("mitmproxy")
    from mitmproxy.tools.main import mitmdump

    args = [
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        "8080",
        "-s",
        str(script_path),
        "--set",
        "termlog_verbosity=info",
        "--set",
        "flow_detail=0",
        "--set",
        "console_eventlog_verbosity=error",
    ]
    mitmdump(args)


def launch_mitm_child(script_path: Path, work_dir: Path):
    entrypoint = current_entrypoint()
    creationflags = 0
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

    if getattr(sys, "frozen", False):
        command = [str(entrypoint), MITM_CHILD_FLAG, str(script_path)]
    else:
        command = [sys.executable, str(entrypoint), MITM_CHILD_FLAG, str(script_path)]

    return subprocess.Popen(
        command,
        cwd=str(work_dir),
        creationflags=creationflags,
    )


def parent_main():
    original_state = read_proxy_state()
    work_dir = Path.cwd()
    state_file = work_dir / "proxy_backup.json"
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(original_state, f, ensure_ascii=False, indent=2)

    print("[+] 已备份当前系统代理设置")

    proc = None
    pac_server = None
    viewer_server = None
    temp_dir_obj = tempfile.TemporaryDirectory(prefix="ballsniff_")
    try:
        temp_dir = Path(temp_dir_obj.name)
        script_path = write_embedded_script(temp_dir)

        print("[+] 已释放内置抓取脚本")
        print("[+] 正在启动内置 mitm 进程...")
        proc = launch_mitm_child(script_path, work_dir)

        if not wait_for_port("127.0.0.1", 8080, 25):
            raise RuntimeError("内置 mitm 没有在 8080 启动成功")

        print("[+] 正在启动本地 PAC 服务...")
        pac_server = start_pac_server(PROXY_SERVER)
        if not wait_for_port("127.0.0.1", 8090, 10):
            raise RuntimeError("PAC 服务没有在 8090 启动成功")

        pac_url = f"http://{PAC_SERVER}{PAC_PATH}"
        print(f"[+] 正在设置系统 PAC 代理: {pac_url}")
        set_system_proxy_pac(pac_url)
        print("[+] 正在确认系统 PAC 代理是否真的生效...")
        verify_system_proxy_pac(pac_url)
        print("[+] 已确认系统 PAC 代理已生效")
        viewer_server, viewer_url = start_viewer_server(work_dir)
        print(f"[+] viewer ready: {viewer_url}")
        open_viewer_page(viewer_url)
        print("[!] 如果还是抓不到 kf.qq.com，请优先怀疑目标进程没有走系统代理，而不是 PAC 没生效")

        print("[+] 系统已切换为按 URL 精确代理")
        print(f"[+] 只有 {TARGET_HOST}{TARGET_PATH} 会经过内置 mitm，其他流量直连")
        print("[+] 打开目标页面后，抓取结果会写入当前目录的 full_list.json")
        print("[+] 完成后按 Enter 或 Ctrl+C 退出")

        try:
            input()
        except KeyboardInterrupt:
            pass

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[错误] {e}")
    finally:
        print("[+] 正在恢复系统代理...")
        try:
            restore_proxy_state(original_state)
            print("[+] 系统代理已恢复")
        except Exception as e:
            print(f"[警告] 恢复代理失败: {e}")
            print(f"[提示] 备份文件在: {state_file}")

        if pac_server is not None:
            try:
                pac_server.shutdown()
                pac_server.server_close()
            except Exception:
                pass

        if viewer_server is not None:
            try:
                viewer_server.shutdown()
                viewer_server.server_close()
            except Exception:
                pass

        if proc is not None:
            print("[+] 正在关闭内置 mitm...")
            try:
                proc.send_signal(signal.CTRL_BREAK_EVENT)
                time.sleep(1)
            except Exception:
                pass

            try:
                proc.terminate()
                proc.wait(timeout=8)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        temp_dir_obj.cleanup()
        print("[+] 已退出")


def parent_main_v2():
    original_state = read_proxy_state()
    work_dir = Path.cwd()
    state_file = work_dir / "proxy_backup.json"
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(original_state, f, ensure_ascii=False, indent=2)

    print("[+] 已备份当前系统代理设置")

    proc = None
    viewer_server = None
    temp_dir_obj = tempfile.TemporaryDirectory(prefix="ballsniff_")
    try:
        temp_dir = Path(temp_dir_obj.name)
        script_path = write_embedded_script(temp_dir)

        print("[+] 已释放内置抓取脚本")
        print("[+] 正在启动内置 mitm 进程...")
        proc = launch_mitm_child(script_path, work_dir)

        if not wait_for_port("127.0.0.1", 8080, 25):
            raise RuntimeError("内置 mitm 没有在 8080 启动成功")

        print(f"[+] 正在设置系统直连代理: {PROXY_SERVER}")
        set_system_proxy_server(PROXY_SERVER)
        print("[+] 正在确认系统直连代理是否真的生效...")
        verify_system_proxy_server(PROXY_SERVER)
        print("[+] 已确认系统直连代理已生效")

        viewer_server, viewer_url = start_viewer_server(work_dir)

        print()
        print("========== 使用教程 ==========")
        print("1. 打开游戏内客服中心")
        print("2. 选择「道具」→「道具流水」")
        print("3. 等待工具自动获取全部流水数据")
        print("4. 获取开始后你可以手动关闭客服页面，工具会在后台继续拉取")
        print("5. 获取完成后在浏览器中查看结果")
        print("   查看地址: " + viewer_url)
        print("==============================")
        print()
        print("[+] 完成后按 Enter 或 Ctrl+C 退出")

        try:
            input()
        except KeyboardInterrupt:
            pass

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[错误] {e}")
    finally:
        print("[+] 正在恢复系统代理...")
        try:
            restore_proxy_state(original_state)
            print("[+] 系统代理已恢复")
        except Exception as e:
            print(f"[警告] 恢复代理失败: {e}")
            print(f"[提示] 备份文件在: {state_file}")

        if viewer_server is not None:
            try:
                viewer_server.shutdown()
                viewer_server.server_close()
            except Exception:
                pass

        if proc is not None:
            print("[+] 正在关闭内置 mitm...")
            try:
                proc.send_signal(signal.CTRL_BREAK_EVENT)
                time.sleep(1)
            except Exception:
                pass

            try:
                proc.terminate()
                proc.wait(timeout=8)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        temp_dir_obj.cleanup()
        print("[+] 已退出")


def main():
    if not getattr(sys, "frozen", False):
        ensure_python_package("mitmproxy")

    if len(sys.argv) >= 3 and sys.argv[1] == MITM_CHILD_FLAG:
        run_embedded_mitm(Path(sys.argv[2]))
        return

    parent_main_v2()


if __name__ == "__main__":
    main()
