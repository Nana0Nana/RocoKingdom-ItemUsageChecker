import gzip
import heapq
import json
import os
import threading
import time
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from copy import deepcopy

from mitmproxy import ctx, http


TARGET_HOST = "kf.qq.com"
TARGET_PATH = "/cgi-bin/commonNew"
TARGET_COMMAND = "F11129"

OUTPUT_FILE = "full_list.json"
DEBUG_RAW_FILE = "debug_page0_raw.txt"
DEBUG_JSON_FILE = "debug_page0_parsed.json"

INCREMENTAL_CONCURRENCY = 8
FULL_FETCH_CONCURRENCY = 20
EMPTY_STREAK_LIMIT = 5
BACKOFF_BASE_SECONDS = 0.5
BACKOFF_MAX_SECONDS = 8.0
MAX_PAGES_SAFETY = 20000
TIMESTAMP_FIELD = "dtEventTime"
REQUEST_SEMAPHORE_LIMIT = 20
EXPECTED_PAGE_SIZE = 15
PROGRESS_LOG_INTERVAL_SECONDS = 5.0
LOOK_AHEAD_MULTIPLIER = 3

START_PAGE_ENV = "BALLSNIFF_START_PAGE"
RESUME_MODE_ENV = "BALLSNIFF_RESUME_MODE"


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


def compute_backoff(attempt: int, base: float = BACKOFF_BASE_SECONDS, cap: float = BACKOFF_MAX_SECONDS) -> float:
    attempt = max(0, int(attempt))
    return min(cap, base * (2 ** attempt))


def row_cache_key(row):
    return json.dumps(row, ensure_ascii=False, sort_keys=True)


def parse_row_timestamp(row):
    if not isinstance(row, dict):
        return None
    value = row.get(TIMESTAMP_FIELD)
    if not value:
        return None
    try:
        return time.strptime(str(value), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def load_existing_cache(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            cached = json.load(f)
    except Exception:
        return [], None, None

    rows = cached.get("rows", [])
    table_head = cached.get("table_head")
    latest_value = None
    latest_ts = None
    for row in rows:
        parsed = parse_row_timestamp(row)
        if parsed is None:
            continue
        if latest_ts is None or parsed > latest_ts:
            latest_ts = parsed
            latest_value = row.get(TIMESTAMP_FIELD)
    return rows, table_head, latest_value


def merge_rows_preserve_order(new_rows, cached_rows):
    cached_keys = {row_cache_key(row) for row in cached_rows}
    new_seen = set()
    merged_new_rows = []
    for row in new_rows:
        key = row_cache_key(row)
        if key in cached_keys or key in new_seen:
            continue
        new_seen.add(key)
        merged_new_rows.append(row)
    return merged_new_rows + list(cached_rows)


def merge_rows_append(cached_rows, new_rows):
    """Resume mode: append new (older) rows AFTER cached rows, deduplicated."""
    cached_keys = {row_cache_key(row) for row in cached_rows}
    new_seen = set()
    merged = list(cached_rows)
    for row in new_rows:
        key = row_cache_key(row)
        if key in cached_keys or key in new_seen:
            continue
        new_seen.add(key)
        merged.append(row)
    return merged


def page_is_older_than_cache(page_rows, cached_latest_value):
    if not cached_latest_value or not page_rows:
        return False
    try:
        cached_ts = time.strptime(str(cached_latest_value), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return False

    page_ts_values = [parse_row_timestamp(row) for row in page_rows]
    page_ts_values = [value for value in page_ts_values if value is not None]
    if not page_ts_values:
        return False
    return max(page_ts_values) < cached_ts


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


def extract_api_has_next(obj, resultinfo, entries):
    candidate_keys = ("has_next_page", "hasNextPage", "hasnextpage", "next_page", "nextpage")

    def normalize_flag(value):
        if value is None:
            return None
        text = str(value).strip().lower()
        if text in ("1", "true", "yes"):
            return True
        if text in ("0", "false", "no"):
            return False
        return None

    for container in (obj, resultinfo):
        if not isinstance(container, dict):
            continue
        for key in candidate_keys:
            if key in container:
                return normalize_flag(container.get(key)), key

    entry_flag = None
    entry_key = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in candidate_keys:
            if key in entry:
                entry_key = key
                current_flag = normalize_flag(entry.get(key))
                if current_flag is True:
                    return True, f"entry.{key}"
                if current_flag is False and entry_flag is None:
                    entry_flag = False
    if entry_key is not None:
        return entry_flag, f"entry.{entry_key}"
    return None, "missing"


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


def http_get_text(url: str, headers: dict, timeout: int = 20, semaphore=None) -> str:
    req_headers = dict(headers)
    req_headers["Accept-Encoding"] = "gzip, deflate"

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers=req_headers, method="GET")
    if semaphore is not None:
        semaphore.acquire()
    try:
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
    finally:
        if semaphore is not None:
            semaphore.release()


def read_env_start_page() -> int:
    """1-indexed env value → 0-indexed page number. 0/invalid → 0."""
    val = os.environ.get(START_PAGE_ENV, "").strip()
    if not val:
        return 0
    try:
        n = int(val)
        return max(0, n - 1)
    except Exception:
        return 0


def is_resume_mode() -> bool:
    return os.environ.get(RESUME_MODE_ENV, "").strip() in ("1", "true", "yes")


def format_elapsed(seconds: float) -> str:
    total = max(0.0, float(seconds))
    minutes = int(total // 60)
    secs = total - minutes * 60
    if minutes >= 60:
        hours = minutes // 60
        minutes = minutes % 60
        return f"{hours}小时{minutes}分{secs:.1f}秒"
    if minutes > 0:
        return f"{minutes}分{secs:.1f}秒"
    return f"{secs:.1f}秒"


class FullFetcher:
    def __init__(self):
        self.running = False
        self.finished = False
        self.request_slots = threading.BoundedSemaphore(REQUEST_SEMAPHORE_LIMIT)

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
        """Single HTTP attempt. Returns (page_num, rows_or_None, has_next, table_head, is_partial, has_next_source)."""
        try:
            text = http_get_text(url, headers=headers, timeout=20, semaphore=self.request_slots).strip()
            obj = extract_json_payload(text)
            if obj is None:
                l, r = text.find("{"), text.rfind("}")
                if l != -1 and r != -1 and r > l:
                    obj = safe_json_loads(text[l : r + 1])
            if not obj:
                return page_num, None, None, None, False, "missing"

            resultinfo = normalize_resultinfo(obj.get("resultinfo", {}))
            entries = resultinfo.get("list", [])

            page_rows = []
            th = None
            for entry in entries:
                data = decode_url_json(entry.get("data", ""))
                th_entry = decode_url_json(entry.get("table_head", ""))
                if isinstance(data, list):
                    page_rows.extend(data)
                if th_entry and th is None:
                    th = th_entry

            has_next_page, has_next_source = extract_api_has_next(obj, resultinfo, entries)
            is_partial_page = bool(
                has_next_page is True and len(page_rows) < EXPECTED_PAGE_SIZE
            )
            return page_num, page_rows, has_next_page, th, is_partial_page, has_next_source
        except Exception:
            return page_num, None, None, None, False, "missing"

    def _fetch_parallel(
        self,
        parsed,
        outer_params,
        base_inner,
        headers,
        start_page,
        cached_latest_value=None,
        concurrency=FULL_FETCH_CONCURRENCY,
        use_cache_boundary=True,
    ):
        """Streaming parallel fetch.

        - New-page submissions are throttled via `new_pages_in_flight` (bounded by `concurrency`),
          independent of retries. Retries never consume the new-page budget, so new pages keep
          flowing even when many retries are waiting in the heap or running.
        - Retries use non-blocking heap-based exponential backoff: a waiting retry does NOT hold
          a worker slot. When its ready_time arrives the main loop dispatches it.
        """
        all_rows = []
        table_head = None
        empty_streak = 0
        updated_pages = 0
        last_successful_page = -1
        last_has_next_flag = "?"
        hit_terminal = False
        hit_cache = False
        new_pages_in_flight = 0
        skipped_pages = []

        executor = ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="fetch")
        in_flight = {}
        completed_results = {}
        retry_counts = {}
        best_results = {}
        pending_retries = []
        retry_seq = 0
        retry_lock = threading.Lock()

        next_submit = start_page
        next_process = start_page
        batch_end = min(start_page + 20, MAX_PAGES_SAFETY)
        last_progress_log = time.time()

        def submit_page(page_num):
            url = self._build_url(parsed, outer_params, base_inner, page_num)
            future = executor.submit(self._fetch_one_page, url, headers, page_num)
            in_flight[future] = page_num

        def schedule_retry(page_num, attempt):
            nonlocal retry_seq
            delay = compute_backoff(attempt - 1)
            ready_time = time.time() + delay
            with retry_lock:
                retry_seq += 1
                heapq.heappush(pending_retries, (ready_time, retry_seq, page_num))
            return delay

        def flush_ready_retries():
            now = time.time()
            ready_pages = []
            with retry_lock:
                while pending_retries and pending_retries[0][0] <= now:
                    _, _, page_num = heapq.heappop(pending_retries)
                    ready_pages.append(page_num)
            for page_num in ready_pages:
                submit_page(page_num)

        def time_until_next_retry():
            with retry_lock:
                if not pending_retries:
                    return None
                return max(0.0, pending_retries[0][0] - time.time())

        def pending_retries_count():
            with retry_lock:
                return len(pending_retries)

        while (
            new_pages_in_flight < concurrency
            and next_submit < batch_end
            and next_submit < MAX_PAGES_SAFETY
        ):
            submit_page(next_submit)
            new_pages_in_flight += 1
            next_submit += 1

        try:
            while in_flight or pending_retries_count() > 0:
                flush_ready_retries()

                if not in_flight:
                    wait_time = time_until_next_retry()
                    if wait_time is None:
                        break
                    time.sleep(min(wait_time + 0.01, 0.2))
                    continue

                wait_timeout = time_until_next_retry()
                if wait_timeout is not None:
                    wait_timeout = max(0.05, min(wait_timeout + 0.01, 1.0))

                done_set, _ = wait(list(in_flight.keys()), timeout=wait_timeout, return_when=FIRST_COMPLETED)

                for future in done_set:
                    page_num = in_flight.pop(future)
                    try:
                        result = future.result()
                    except Exception:
                        result = (page_num, None, None, None, False, "missing")

                    _, page_rows, has_next, th, is_partial, _ = result

                    if th and table_head is None:
                        table_head = th

                    current_len = len(page_rows) if page_rows is not None else -1
                    prev_best = best_results.get(page_num)
                    prev_len = prev_best[0] if prev_best is not None else -2
                    if current_len > prev_len:
                        best_results[page_num] = (current_len, result)

                    attempt = retry_counts.get(page_num, 0)
                    if attempt == 0:
                        new_pages_in_flight -= 1

                    should_retry = False
                    if page_rows is None:
                        should_retry = True
                    elif page_rows == [] and has_next is not False:
                        should_retry = True
                    elif is_partial:
                        should_retry = True

                    if should_retry:
                        new_attempt = attempt + 1
                        retry_counts[page_num] = new_attempt
                        delay = schedule_retry(page_num, new_attempt)
                        self.log(f"[retry] page {page_num + 1} 第 {new_attempt} 次重试")
                    else:
                        _, final_result = best_results.get(page_num, (-1, result))
                        completed_results[page_num] = final_result

                while next_process in completed_results:
                    result = completed_results.pop(next_process)
                    _, page_rows, has_next, _, is_partial, has_next_source = result

                    raw_count = len(page_rows)
                    all_rows.extend(page_rows)

                    hit_cache_boundary = use_cache_boundary and page_is_older_than_cache(page_rows, cached_latest_value)
                    if raw_count > 0 and not hit_cache_boundary:
                        updated_pages += 1

                    if raw_count > 0:
                        last_successful_page = next_process
                        last_has_next_flag = "1" if has_next is True else "0" if has_next is False else "?"

                    has_next_flag_display = "1" if has_next is True else "0" if has_next is False else "-"
                    if is_partial:
                        self.log(
                            f"page {next_process + 1} 接口返回{raw_count}条 has_next={has_next_flag_display} 当前累计 {len(all_rows)}条 [警告: 少于预期{EXPECTED_PAGE_SIZE}条 {has_next_source}]"
                        )
                    else:
                        self.log(
                            f"page {next_process + 1} 接口返回{raw_count}条 has_next={has_next_flag_display} 当前累计 {len(all_rows)}条 {has_next_source}"
                        )

                    if not page_rows:
                        empty_streak += 1
                    else:
                        empty_streak = 0

                    next_process += 1

                    if empty_streak >= EMPTY_STREAK_LIMIT:
                        hit_terminal = True
                        self.log(f"[done] 连续 {EMPTY_STREAK_LIMIT} 页为空，获取完成")
                        break

                    if hit_cache_boundary:
                        hit_cache = True
                        self.log(f"[done] 已命中本地缓存边界 page {next_process}")
                        break

                    if has_next is False and raw_count > 0:
                        hit_terminal = True
                        self.log(f"[done] 接口已返回末页 page {next_process}，获取完成")
                        break

                if hit_terminal or hit_cache:
                    for future in list(in_flight.keys()):
                        future.cancel()
                    with retry_lock:
                        pending_retries.clear()
                    break

                if next_process >= batch_end:
                    batch_end = min(next_process + 20, MAX_PAGES_SAFETY)

                flush_ready_retries()
                while (
                    new_pages_in_flight < concurrency
                    and next_submit < batch_end
                    and next_submit < MAX_PAGES_SAFETY
                ):
                    submit_page(next_submit)
                    new_pages_in_flight += 1
                    next_submit += 1

                now = time.time()
                if now - last_progress_log >= PROGRESS_LOG_INTERVAL_SECONDS:
                    retrying = pending_retries_count()
                    running = len(in_flight)
                    waiting_in_order = len(completed_results)
                    stuck_attempt = retry_counts.get(next_process, 0)
                    stuck_hint = f" | 卡在 page {next_process + 1} retry {stuck_attempt}" if stuck_attempt > 0 else ""
                    self.log(
                        f"[progress] 已落地至 page {next_process} | 已提交至 page {next_submit} | "
                        f"等待前序 {waiting_in_order} 页 | 在途 {running} | 重试排队 {retrying} | "
                        f"新页槽位 {new_pages_in_flight}/{concurrency}{stuck_hint}"
                    )
                    last_progress_log = now
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        if hit_terminal or hit_cache:
            last_has_next_flag = "0"

        last_page_1indexed = last_successful_page + 1 if last_successful_page >= 0 else 0
        return all_rows, table_head, updated_pages, last_page_1indexed, last_has_next_flag, skipped_pages

    def fetch_all_from_flow(self, flow: http.HTTPFlow):
        start_time = time.time()
        try:
            req = flow.request
            parsed = urllib.parse.urlparse(req.pretty_url)
            outer_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            outer_params = {k: v[0] for k, v in outer_qs.items()}

            command_outer = outer_params.get("command", "")
            inner_params = parse_inner_command(command_outer)

            self.log("正在获取道具流水...")

            base_inner = deepcopy(inner_params)
            env_start = read_env_start_page()
            resume_mode = is_resume_mode()
            if env_start > 0:
                start_page = env_start
                self.log(f"[resume] 从第 {start_page + 1} 页继续拉取 (pageindex={start_page})")
            else:
                start_page = int(base_inner.get("pageindex", "0"))

            headers = dict(req.headers)
            headers.pop("Content-Length", None)
            headers.pop("Transfer-Encoding", None)
            headers.pop("Host", None)
            headers.pop("Connection", None)

            cached_rows, cached_table_head, cached_latest_value = load_existing_cache(OUTPUT_FILE)
            use_cache_boundary = bool(cached_rows) and not resume_mode
            concurrency = 20
            if resume_mode:
                self.log(f"[resume] 恢复模式, cached {len(cached_rows)} rows, concurrency={concurrency}")
            elif cached_latest_value:
                self.log(f"[cache] loaded {len(cached_rows)} rows, latest {cached_latest_value}, incremental mode, concurrency={concurrency}")
            else:
                self.log(f"[cache] no cache found, full fetch mode, concurrency={concurrency}")

            new_rows, table_head, updated_pages, last_page_1indexed, last_has_next, skipped_pages = self._fetch_parallel(
                parsed,
                outer_params,
                base_inner,
                headers,
                start_page,
                cached_latest_value,
                concurrency,
                use_cache_boundary,
            )

            if resume_mode:
                merged_rows = merge_rows_append(cached_rows, new_rows)
            else:
                merged_rows = merge_rows_preserve_order(new_rows, cached_rows)
            added_rows = len(merged_rows) - len(cached_rows)
            if table_head is None:
                table_head = cached_table_head

            out = {
                "count": len(merged_rows),
                "table_head": table_head,
                "rows": merged_rows,
                "page": last_page_1indexed,
                "has_next": last_has_next,
                "skipped_pages": skipped_pages,
            }

            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)

            elapsed = time.time() - start_time
            self.finished = True
            self.log(f"[saved] 已写入 {OUTPUT_FILE}  共 {len(merged_rows)}条")
            self.log(
                f"本次用时 {format_elapsed(elapsed)} 拉取了 {updated_pages} 页 {added_rows} 条道具信息"
            )
            if skipped_pages:
                preview = ", ".join(str(p) for p in skipped_pages[:20])
                more = f" ...(共{len(skipped_pages)}页)" if len(skipped_pages) > 20 else ""
                self.log(f"[skipped] 被跳过的页: {preview}{more} — 可用断点续传补拉")
            self.log(f"[meta] page={last_page_1indexed} has_next={last_has_next}")
            try:
                ctx.master.shutdown()
            except Exception as shutdown_error:
                self.log(f"[warn] 自动关闭代理失败: {shutdown_error}")

        except Exception as e:
            self.log(f"[exception] {type(e).__name__}: {e}")
        finally:
            self.running = False


addons = [FullFetcher()]
