using System.Net;
using System.Runtime.Versioning;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace RocoKingdom.ItemUsageChecker;

[SupportedOSPlatform("windows")]
public sealed class MitmEngine : IDisposable
{
    private readonly ProxyServer _proxy;
    private readonly ExplicitProxyEndPoint _endpoint;
    private readonly ItemUsageFetcher _fetcher;

    public MitmEngine(string host, int port, ItemUsageFetcher fetcher)
    {
        _fetcher = fetcher;
        _proxy = new ProxyServer();

        _proxy.CertificateManager.CreateRootCertificate(persistToFile: true);
        _proxy.CertificateManager.TrustRootCertificate(machineTrusted: false);

        IPAddress ipAddress = host == "127.0.0.1" ? IPAddress.Loopback : IPAddress.Parse(host);
        _endpoint = new ExplicitProxyEndPoint(ipAddress, port, decryptSsl: true);
        _endpoint.BeforeTunnelConnectRequest += OnBeforeTunnelConnect;

        _proxy.AddEndPoint(_endpoint);
        _proxy.BeforeRequest += OnBeforeRequest;
        _proxy.BeforeResponse += OnBeforeResponse;
    }

    public void Start()
    {
        _proxy.Start();
    }

    private static Task OnBeforeTunnelConnect(object sender, TunnelConnectSessionEventArgs e)
    {
        string host = e.HttpClient.Request.RequestUri.Host;
        if (!host.Equals(ItemUsageFetcher.TARGET_HOST, StringComparison.OrdinalIgnoreCase))
        {
            e.DecryptSsl = false;
        }
        return Task.CompletedTask;
    }

    private static Task OnBeforeRequest(object sender, SessionEventArgs e)
    {
        string host = e.HttpClient.Request.RequestUri.Host;
        if (!host.Equals(ItemUsageFetcher.TARGET_HOST, StringComparison.OrdinalIgnoreCase))
        {
            e.GenericResponse(string.Empty, HttpStatusCode.Forbidden);
        }
        return Task.CompletedTask;
    }

    private Task OnBeforeResponse(object sender, SessionEventArgs e)
    {
        _fetcher.TryStart(e);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        try
        {
            if (_proxy.ProxyRunning) _proxy.Stop();
        }
        catch
        {
            // ignore
        }
        try
        {
            _proxy.Dispose();
        }
        catch
        {
            // ignore
        }
    }
}
