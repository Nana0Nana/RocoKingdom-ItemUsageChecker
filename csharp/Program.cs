using System.Runtime.Versioning;
using System.Text.Encodings.Web;
using System.Text.Json;
using RocoKingdom.ItemUsageChecker;

[assembly: SupportedOSPlatform("windows")]

const string PROXY_SERVER = "127.0.0.1:8080";
const int PROXY_PORT = 8080;
const string VIEWER_HOST = "127.0.0.1";

string workDir = Directory.GetCurrentDirectory();
string stateFile = Path.Combine(workDir, "proxy_backup.json");

var originalState = SystemProxyManager.ReadState();
var backupOptions = new JsonSerializerOptions
{
    WriteIndented = true,
    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
};
File.WriteAllText(stateFile, JsonSerializer.Serialize(originalState, backupOptions));
Console.WriteLine("[+] 已备份当前系统代理设置");

MitmEngine? mitm = null;
ViewerServer? viewer = null;

using var exitEvent = new ManualResetEventSlim(false);
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    exitEvent.Set();
};

try
{
    Console.WriteLine("[+] 正在启动内置 mitm 代理...");
    var fetcher = new ItemUsageFetcher(workDir);
    mitm = new MitmEngine(VIEWER_HOST, PROXY_PORT, fetcher);
    mitm.Start();

    Console.WriteLine($"[+] 正在设置系统直连代理: {PROXY_SERVER}");
    SystemProxyManager.SetDirectProxy(PROXY_SERVER);
    Console.WriteLine("[+] 正在确认系统直连代理是否真的生效...");
    SystemProxyManager.VerifyDirectProxy(PROXY_SERVER);
    Console.WriteLine("[+] 已确认系统直连代理已生效");

    viewer = new ViewerServer(VIEWER_HOST, workDir);
    string viewerUrl = viewer.Start();

    Console.WriteLine();
    Console.WriteLine("========== 使用教程 ==========");
    Console.WriteLine("1. 打开游戏内客服中心");
    Console.WriteLine("2. 选择「道具」→「道具流水」");
    Console.WriteLine("3. 等待工具自动获取全部流水数据");
    Console.WriteLine("4. 获取开始后你可以手动关闭客服页面，工具会在后台继续拉取");
    Console.WriteLine("5. 获取完成后在浏览器中查看结果");
    Console.WriteLine($"   查看地址: {viewerUrl}");
    Console.WriteLine("==============================");
    Console.WriteLine();
    Console.WriteLine("[+] 完成后按 Enter 或 Ctrl+C 退出");

    var readTask = Task.Run(() =>
    {
        try { Console.ReadLine(); } catch { /* ignore */ }
    });
    var exitTask = Task.Run(() => exitEvent.Wait());
    await Task.WhenAny(readTask, exitTask);
}
catch (Exception ex)
{
    Console.WriteLine($"[错误] {ex.Message}");
}
finally
{
    Console.WriteLine("[+] 正在恢复系统代理...");
    try
    {
        SystemProxyManager.RestoreState(originalState);
        Console.WriteLine("[+] 系统代理已恢复");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[警告] 恢复代理失败: {ex.Message}");
        Console.WriteLine($"[提示] 备份文件在: {stateFile}");
    }

    viewer?.Dispose();

    if (mitm != null)
    {
        Console.WriteLine("[+] 正在关闭内置 mitm...");
        mitm.Dispose();
    }

    Console.WriteLine("[+] 已退出");
}
