using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;

namespace RocoKingdom.ItemUsageChecker;

[SupportedOSPlatform("windows")]
public sealed class ViewerServer : IDisposable
{
    private readonly string _host;
    private readonly string _workDir;
    private readonly HttpListener _listener = new();
    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private int _port;

    public ViewerServer(string host, string workDir)
    {
        _host = host;
        _workDir = workDir;
    }

    public string Start()
    {
        _port = FindAvailablePort(_host);
        _listener.Prefixes.Add($"http://{_host}:{_port}/");
        _listener.Start();

        _cts = new CancellationTokenSource();
        _loopTask = Task.Run(() => LoopAsync(_cts.Token));

        string url = $"http://{_host}:{_port}/viewer.html";
        OpenBrowser(url);
        return url;
    }

    private static int FindAvailablePort(string host)
    {
        using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        sock.Bind(new IPEndPoint(IPAddress.Parse(host), 0));
        return ((IPEndPoint)sock.LocalEndPoint!).Port;
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync();
            }
            catch (HttpListenerException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (InvalidOperationException) { break; }

            _ = Task.Run(() => HandleRequest(ctx));
        }
    }

    private void HandleRequest(HttpListenerContext ctx)
    {
        try
        {
            string path = ctx.Request.Url?.AbsolutePath ?? "/";
            byte[] body;
            string contentType;

            if (path == "/" || path == "/viewer.html")
            {
                string viewerFile = Path.Combine(_workDir, "viewer.html");
                if (!File.Exists(viewerFile))
                {
                    WriteError(ctx, 404, "viewer.html not found");
                    return;
                }
                body = File.ReadAllBytes(viewerFile);
                contentType = "text/html; charset=utf-8";
            }
            else if (path == "/full_list.json")
            {
                string jsonFile = Path.Combine(_workDir, "full_list.json");
                if (!File.Exists(jsonFile))
                {
                    WriteError(ctx, 404, "full_list.json not found");
                    return;
                }
                body = File.ReadAllBytes(jsonFile);
                contentType = "application/json; charset=utf-8";
            }
            else
            {
                WriteError(ctx, 404, "Not Found");
                return;
            }

            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = contentType;
            ctx.Response.Headers["Cache-Control"] = "no-store";
            ctx.Response.ContentLength64 = body.Length;
            ctx.Response.OutputStream.Write(body, 0, body.Length);
            ctx.Response.OutputStream.Close();
        }
        catch
        {
            // swallow
        }
    }

    private static void WriteError(HttpListenerContext ctx, int status, string message)
    {
        try
        {
            ctx.Response.StatusCode = status;
            byte[] bytes = Encoding.UTF8.GetBytes(message);
            ctx.Response.ContentLength64 = bytes.Length;
            ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            ctx.Response.OutputStream.Close();
        }
        catch { /* ignore */ }
    }

    private static void OpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[warn] failed to open browser automatically: {ex.Message}");
            Console.WriteLine($"[hint] open this URL manually: {url}");
        }
    }

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { /* ignore */ }
        try { _listener.Stop(); } catch { /* ignore */ }
        try { _listener.Close(); } catch { /* ignore */ }
    }
}
