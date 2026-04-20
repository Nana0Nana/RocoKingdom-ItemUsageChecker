using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RocoKingdom.ItemUsageChecker.Helpers;

public static class JsonHelpers
{
    private static readonly JsonSerializerOptions DebugSerializerOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static JsonNode? SafeJsonParse(string? s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        try
        {
            return JsonNode.Parse(s);
        }
        catch
        {
            return null;
        }
    }

    public static JsonNode? DecodeUrlJson(string? s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        try
        {
            return JsonNode.Parse(Uri.UnescapeDataString(s));
        }
        catch
        {
            return null;
        }
    }

    public static JsonNode? ExtractJsonPayload(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        string stripped = text.Trim();
        if (stripped.Length == 0) return null;

        var candidates = new List<string> { stripped };
        try { candidates.Add(Uri.UnescapeDataString(stripped)); } catch { /* ignore */ }
        try { candidates.Add(Uri.UnescapeDataString(stripped.Replace('+', ' '))); } catch { /* ignore */ }

        var seen = new HashSet<string>();
        foreach (var candidate in candidates)
        {
            if (!seen.Add(candidate)) continue;

            var obj = SafeJsonParse(candidate);
            if (obj != null) return obj;

            foreach (var (left, right) in new[] { ('{', '}'), ('[', ']') })
            {
                int l = candidate.IndexOf(left);
                int r = candidate.LastIndexOf(right);
                if (l != -1 && r != -1 && r > l)
                {
                    obj = SafeJsonParse(candidate.Substring(l, r - l + 1));
                    if (obj != null) return obj;
                }
            }
        }

        return null;
    }

    public static JsonNode NormalizeResultInfo(JsonNode? value)
    {
        if (value is JsonObject obj) return obj;
        if (value is JsonValue jv && jv.TryGetValue<string>(out var s))
        {
            return ExtractJsonPayload(s) ?? new JsonObject();
        }
        return new JsonObject();
    }

    public static string DedupeKey(JsonNode? row)
    {
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms))
        {
            WriteSorted(writer, row);
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static void WriteSorted(Utf8JsonWriter writer, JsonNode? node)
    {
        switch (node)
        {
            case null:
                writer.WriteNullValue();
                break;
            case JsonObject obj:
                writer.WriteStartObject();
                foreach (var kv in obj.OrderBy(k => k.Key, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(kv.Key);
                    WriteSorted(writer, kv.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonArray arr:
                writer.WriteStartArray();
                foreach (var item in arr)
                {
                    WriteSorted(writer, item);
                }
                writer.WriteEndArray();
                break;
            case JsonValue val:
                val.WriteTo(writer);
                break;
        }
    }

    public static void DumpDebugFiles(string workDir, string rawText, JsonNode? parsed)
    {
        try
        {
            File.WriteAllText(Path.Combine(workDir, "debug_page0_raw.txt"), rawText);
        }
        catch { /* ignore */ }

        try
        {
            string json = parsed != null
                ? parsed.ToJsonString(DebugSerializerOptions)
                : "{\"error\":\"json_parse_failed\"}";
            File.WriteAllText(Path.Combine(workDir, "debug_page0_parsed.json"), json);
        }
        catch { /* ignore */ }
    }
}
