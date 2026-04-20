using System.Net;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using RocoKingdom.ItemUsageChecker.Helpers;
using Titanium.Web.Proxy.EventArguments;

namespace RocoKingdom.ItemUsageChecker;

[SupportedOSPlatform("windows")]
public sealed class ItemUsageFetcher
{
    public const string TARGET_HOST = "kf.qq.com";
    public const string TARGET_PATH = "/cgi-bin/commonNew";
    public const string TARGET_COMMAND = "F11129";
    private const string OUTPUT_FILE = "full_list.json";
    private const int MAX_PAGES = 2000;

    private static readonly JsonSerializerOptions OutputSerializerOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly string _workDir;
    private int _running;
    private int _finished;

    public ItemUsageFetcher(string workDir)
    {
        _workDir = workDir;
    }

    public bool IsFinished => Interlocked.CompareExchange(ref _finished, 0, 0) == 1;
    public bool IsRunning => Interlocked.CompareExchange(ref _running, 0, 0) == 1;

    public void TryStart(SessionEventArgs e)
    {
        if (IsFinished || IsRunning) return;
        if (!MatchTarget(e)) return;

        if (Interlocked.CompareExchange(ref _running, 1, 0) != 0) return;

        var req = e.HttpClient.Request;
        string url = req.Url;
        var headers = new List<(string Name, string Value)>();
        foreach (var h in req.Headers)
        {
            headers.Add((h.Name, h.Value));
        }

        _ = Task.Run(() => FetchAllAsync(url, headers));
    }

    private static bool MatchTarget(SessionEventArgs e)
    {
        var req = e.HttpClient.Request;
        var uri = req.RequestUri;

        if (!string.Equals(uri.Host, TARGET_HOST, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.Equals(uri.AbsolutePath, TARGET_PATH, StringComparison.Ordinal))
            return false;

        var outerParams = UrlCommandHelpers.ParseQueryString(uri.Query);
        string commandOuter = outerParams.GetValueOrDefault("command", string.Empty);
        if (string.IsNullOrEmpty(commandOuter)) return false;

        var inner = UrlCommandHelpers.ParseInnerCommand(commandOuter);
        return inner.GetValueOrDefault("command") == TARGET_COMMAND;
    }

    private async Task FetchAllAsync(string url, List<(string Name, string Value)> requestHeaders)
    {
        try
        {
            var uri = new Uri(url);
            var outerParams = UrlCommandHelpers.ParseQueryString(uri.Query);
            string commandOuter = outerParams.GetValueOrDefault("command", string.Empty);
            var baseInner = UrlCommandHelpers.ParseInnerCommand(commandOuter);

            Log("正在获取道具流水...");

            int pageIndex = int.TryParse(baseInner.GetValueOrDefault("pageindex", "0"), out var pi) ? pi : 0;
            int pageSize = int.TryParse(baseInner.GetValueOrDefault("pagesize", "15"), out var ps) ? ps : 15;

            var filteredHeaders = requestHeaders
                .Where(h => !IsHopByHop(h.Name))
                .ToList();

            using var handler = new HttpClientHandler
            {
                UseProxy = false,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };

            var allRows = new List<JsonNode>();
            var seenKeys = new HashSet<string>();
            JsonNode? tableHead = null;
            int emptyPageStreak = 0;
            int duplicatePageStreak = 0;

            for (int i = 0; i < MAX_PAGES; i++)
            {
                var currentInner = new Dictionary<string, string>(baseInner, StringComparer.Ordinal)
                {
                    ["pageindex"] = (pageIndex + i).ToString(),
                    ["pagesize"] = pageSize.ToString(),
                };

                var currentOuter = new Dictionary<string, string>(outerParams, StringComparer.Ordinal)
                {
                    ["command"] = UrlCommandHelpers.RebuildInnerCommand(currentInner),
                };
                if (currentOuter.ContainsKey("t"))
                {
                    currentOuter["t"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
                }

                string query = UrlCommandHelpers.BuildQueryString(currentOuter);
                var builder = new UriBuilder(uri) { Query = query };
                string pageUrl = builder.Uri.AbsoluteUri;

                Log($"[fetch] pageindex={currentInner["pageindex"]}");

                const int MAX_RETRIES = 3;
                JsonNode? obj = null;
                string text = string.Empty;

                for (int retry = 0; retry < MAX_RETRIES; retry++)
                {
                    try
                    {
                        text = (await HttpGetTextAsync(http, pageUrl, filteredHeaders)).Trim();
                        obj = JsonHelpers.ExtractJsonPayload(text);

                        if (obj == null)
                        {
                            int l = text.IndexOf('{');
                            int r = text.LastIndexOf('}');
                            if (l != -1 && r != -1 && r > l)
                            {
                                obj = JsonHelpers.SafeJsonParse(text.Substring(l, r - l + 1));
                            }
                        }

                        if (obj != null) break;

                        if (retry < MAX_RETRIES - 1)
                        {
                            Log($"[warn] 第 {retry + 1} 次解析失败，1 秒后重试...");
                            await Task.Delay(1000);
                        }
                    }
                    catch (Exception ex)
                    {
                        if (retry < MAX_RETRIES - 1)
                        {
                            Log($"[warn] 第 {retry + 1} 次请求异常: {ex.Message}，1 秒后重试...");
                            await Task.Delay(1000);
                        }
                        else
                        {
                            Log($"[error] 请求失败: {ex.Message}");
                        }
                    }
                }

                if (obj == null)
                {
                    string snippet = text.Length > 300 ? text[..300] : text;
                    Log($"[error] JSON 解析失败，前 300 字符: {(string.IsNullOrEmpty(snippet) ? "空响应" : snippet)}");
                    if (i == 0) JsonHelpers.DumpDebugFiles(_workDir, text, null);
                    break;
                }

                if (i == 0) JsonHelpers.DumpDebugFiles(_workDir, text, obj);

                if (obj is not JsonObject rootObj)
                {
                    Log($"[error] response is not an object: {obj.GetType().Name}");
                    break;
                }

                var resultInfo = JsonHelpers.NormalizeResultInfo(rootObj["resultinfo"]);
                var entries = (resultInfo as JsonObject)?["list"] as JsonArray;
                if (entries == null)
                {
                    Log("[error] resultinfo.list is not a list");
                    break;
                }

                var pageRows = new List<JsonNode>();
                bool hasNextPage = false;

                foreach (var entry in entries)
                {
                    if (entry is not JsonObject entryObj) continue;

                    string? dataRaw = entryObj["data"]?.GetValue<string>();
                    string? thRaw = entryObj["table_head"]?.GetValue<string>();

                    var data = JsonHelpers.DecodeUrlJson(dataRaw);
                    var th = JsonHelpers.DecodeUrlJson(thRaw);

                    if (data is JsonArray dataArr)
                    {
                        foreach (var row in dataArr)
                        {
                            if (row != null)
                            {
                                pageRows.Add(row.DeepClone());
                            }
                        }
                    }

                    if (th != null && tableHead == null)
                    {
                        tableHead = th.DeepClone();
                    }

                    string? hasNext = entryObj["has_next_page"]?.ToString();
                    if (hasNext == "1") hasNextPage = true;
                }

                int before = allRows.Count;
                foreach (var row in pageRows)
                {
                    string key = JsonHelpers.DedupeKey(row);
                    if (seenKeys.Add(key))
                    {
                        allRows.Add(row);
                    }
                }
                int added = allRows.Count - before;

                Log($"page {i + 1} +{added}条 当前 {allRows.Count}条  has_next={(hasNextPage ? 1 : 0)}");

                if (pageRows.Count == 0) emptyPageStreak++; else emptyPageStreak = 0;
                if (pageRows.Count > 0 && added == 0) duplicatePageStreak++; else duplicatePageStreak = 0;

                if (emptyPageStreak >= 2)
                {
                    Log("[done] 连续 2 页为空，停止继续翻页");
                    break;
                }

                if (duplicatePageStreak >= 3)
                {
                    Log("[done] 连续 3 页没有新增记录，疑似到达末尾，停止继续翻页");
                    break;
                }

                if (!hasNextPage)
                {
                    Log("[hint] has_next_page=0，但继续探测后续页，直到空页或重复页为止");
                }

                await Task.Delay(250);
            }

            var rowsArray = new JsonArray();
            foreach (var row in allRows)
            {
                rowsArray.Add(row);
            }

            var output = new JsonObject
            {
                ["count"] = allRows.Count,
                ["table_head"] = tableHead,
                ["rows"] = rowsArray,
            };

            string outPath = Path.Combine(_workDir, OUTPUT_FILE);
            await File.WriteAllTextAsync(outPath, output.ToJsonString(OutputSerializerOptions), Encoding.UTF8);

            Log($"[saved] wrote {OUTPUT_FILE}");
            Interlocked.Exchange(ref _finished, 1);
        }
        catch (Exception ex)
        {
            Log($"[exception] {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _running, 0);
        }
    }

    private static async Task<string> HttpGetTextAsync(HttpClient client, string url, List<(string Name, string Value)> headers)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        foreach (var (name, value) in headers)
        {
            if (name.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase)) continue;
            if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)) continue;
            request.Headers.TryAddWithoutValidation(name, value);
        }

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        if ((int)response.StatusCode >= 400)
        {
            throw new HttpRequestException($"HTTP {(int)response.StatusCode}");
        }

        byte[] bytes = await response.Content.ReadAsByteArrayAsync();
        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(bytes);
        }
    }

    private static bool IsHopByHop(string name)
        => name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Host", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Connection", StringComparison.OrdinalIgnoreCase);

    private static void Log(string msg) => Console.WriteLine(msg);
}
