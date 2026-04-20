using System.Text;
using System.Web;

namespace RocoKingdom.ItemUsageChecker.Helpers;

public static class UrlCommandHelpers
{
    public static Dictionary<string, string> ParseQueryString(string? query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(query)) return result;

        if (query.StartsWith('?')) query = query[1..];

        var parsed = HttpUtility.ParseQueryString(query);
        foreach (var key in parsed.AllKeys)
        {
            if (key == null) continue;
            result[key] = parsed[key] ?? string.Empty;
        }
        return result;
    }

    public static Dictionary<string, string> ParseInnerCommand(string? commandValue)
    {
        if (string.IsNullOrEmpty(commandValue))
            return new Dictionary<string, string>(StringComparer.Ordinal);

        string decoded = Uri.UnescapeDataString(commandValue);
        return ParseQueryString(decoded);
    }

    public static string RebuildInnerCommand(Dictionary<string, string> innerParams)
        => BuildQueryString(innerParams);

    public static string BuildQueryString(IEnumerable<KeyValuePair<string, string>> parameters)
    {
        var sb = new StringBuilder();
        bool first = true;
        foreach (var kv in parameters)
        {
            if (!first) sb.Append('&');
            sb.Append(HttpUtility.UrlEncode(kv.Key));
            sb.Append('=');
            sb.Append(HttpUtility.UrlEncode(kv.Value));
            first = false;
        }
        return sb.ToString();
    }
}
