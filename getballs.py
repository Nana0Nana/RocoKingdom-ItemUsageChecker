import gzip
import json
import threading
import time
import urllib.parse
import urllib.request
import zlib
from copy import deepcopy

from mitmproxy import ctx, http


TARGET_HOST = "kf.qq.com"
TARGET_PATH = "/cgi-bin/commonNew"
TARGET_COMMAND = "F11129"

OUTPUT_FILE = "full_list.json"
DEBUG_RAW_FILE = "debug_page0_raw.txt"
DEBUG_JSON_FILE = "debug_page0_parsed.json"


def safe_json_loads(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def decode_url_json(text: str):
    if not text:
        return None
    try:
        return json.loads(urllib.parse.unquote(text))
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
        # 只放行目标 host 的请求，其余全部 drop 以静默无关流量
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

    def fetch_all_from_flow(self, flow: http.HTTPFlow):
        try:
            req = flow.request
            parsed = urllib.parse.urlparse(req.pretty_url)
            outer_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            outer_params = {k: v[0] for k, v in outer_qs.items()}

            command_outer = outer_params.get("command", "")
            inner_params = parse_inner_command(command_outer)

            self.log(f"正在获取道具流水...")

            base_inner = deepcopy(inner_params)
            pageindex = int(base_inner.get("pageindex", "0"))
            pagesize = int(base_inner.get("pagesize", "15"))

            headers = dict(req.headers)
            headers.pop("Content-Length", None)
            headers.pop("Transfer-Encoding", None)
            headers.pop("Host", None)
            headers.pop("Connection", None)

            all_rows = []
            table_head = None
            max_pages = 2000
            empty_page_streak = 0
            duplicate_page_streak = 0

            for i in range(max_pages):
                current_inner = deepcopy(base_inner)
                current_inner["pageindex"] = str(pageindex + i)
                current_inner["pagesize"] = str(pagesize)

                current_outer = deepcopy(outer_params)
                current_outer["command"] = rebuild_inner_command(current_inner)
                if "t" in current_outer:
                    current_outer["t"] = str(int(time.time() * 1000))

                url = urllib.parse.urlunparse(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urllib.parse.urlencode(current_outer),
                        parsed.fragment,
                    )
                )

                self.log(f"[fetch] pageindex={current_inner['pageindex']}")

                text = http_get_text(url, headers=headers, timeout=20).strip()
                obj = extract_json_payload(text)
                if obj is None:
                    if i == 0:
                        dump_debug_files(text, {"error": "json_parse_failed"})
                    self.log(f"[error] json parse failed, first 300 chars: {text[:300]}")
                    break

                if i == 0:
                    dump_debug_files(text, obj)

                if not isinstance(obj, dict):
                    self.log(f"[error] response is not an object: {type(obj).__name__}")
                    break

                resultinfo = normalize_resultinfo(obj.get("resultinfo", {}))
                entries = resultinfo.get("list", [])
                if not isinstance(entries, list):
                    self.log(f"[error] resultinfo.list is not a list: {type(entries).__name__}")
                    self.log(f"[debug] wrote {DEBUG_RAW_FILE} and {DEBUG_JSON_FILE}")
                    break

                page_rows = []
                has_next_page = False

                for entry in entries:
                    if not isinstance(entry, dict):
                        continue

                    data = decode_url_json(entry.get("data", ""))
                    th = decode_url_json(entry.get("table_head", ""))

                    if isinstance(data, list):
                        page_rows.extend(data)

                    if th and table_head is None:
                        table_head = th

                    if str(entry.get("has_next_page", "0")) == "1":
                        has_next_page = True

                before = len(all_rows)
                all_rows.extend(page_rows)
                all_rows = dedupe_rows(all_rows)
                added = len(all_rows) - before

                self.log(
                    f"page {i + 1} +{added}条 当前 {len(all_rows)}条  "
                    f"has_next={1 if has_next_page else 0}"
                )

                if not page_rows:
                    empty_page_streak += 1
                else:
                    empty_page_streak = 0

                if page_rows and added == 0:
                    duplicate_page_streak += 1
                else:
                    duplicate_page_streak = 0

                if empty_page_streak >= 2:
                    self.log("[done] stop after 2 empty pages")
                    break

                if duplicate_page_streak >= 3:
                    self.log("[done] stop after 3 duplicate pages")
                    break

                if not has_next_page:
                    self.log("[hint] has_next_page=0, probing more pages until empty/duplicate")

                time.sleep(0.25)

            out = {
                "count": len(all_rows),
                "table_head": table_head,
                "rows": all_rows,
            }

            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)

            self.log(f"[saved] wrote {OUTPUT_FILE}")
            self.finished = True

        except Exception as e:
            self.log(f"[exception] {type(e).__name__}: {e}")
        finally:
            self.running = False


addons = [FullFetcher()]
