import gzip
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
        """拉取单页，返回 (page_num, page_rows, has_next_page, table_head)。"""
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
            return page_num, None, False, None

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
                    batch_size = min(CONCURRENCY, max_pages - fetched)
                    batch_pages = list(range(next_page, next_page + batch_size))

                    futures = {}
                    for p in batch_pages:
                        url = self._build_url(parsed, outer_params, base_inner, p)
                        futures[pool.submit(self._fetch_one_page, url, headers, p)] = p

                    batch_results = []
                    for future in as_completed(futures):
                        result = future.result()
                        batch_results.append(result)

                    batch_results.sort(key=lambda r: r[0])

                    any_empty = False
                    any_dup = False
                    for result in batch_results:
                        page_num = result[0]
                        page_rows = result[1]
                        th = result[3] if len(result) > 3 else None

                        if page_rows is None:
                            any_empty = True
                            continue

                        if th and table_head is None:
                            table_head = th

                        before = len(all_rows)
                        all_rows.extend(page_rows)
                        all_rows = dedupe_rows(all_rows)
                        added = len(all_rows) - before

                        if not page_rows:
                            any_empty = True
                        if page_rows and added == 0:
                            any_dup = True

                        fetched += 1

                    if len(all_rows) > 0:
                        self.log(f"page {fetched} 当前 {len(all_rows)}条")

                    next_page += batch_size

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
