// PQCC .NET client (SslStream). Usage: version | <variant> <mode> <host> <port>
//
// The same program runs on Linux (OpenSSL), Windows (SChannel) and macOS (Apple Security
// framework), so the three rows differ only in the platform TLS stack underneath.
//
// Trust: the variant's root is the only trust anchor (X509ChainTrustMode.CustomRootTrust).
// The platform still builds and verifies the chain, validity, the serverAuth EKU and the
// hostname; nothing is skipped. Certificates come from $PQCC_CERTS (default /certs/out).
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

static class Program
{
    const string P12Pass = "pqcc";
    const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

    static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "version")
        {
            Console.WriteLine(Version());
            return 0;
        }
        string variant = args[0], mode = args[1], host = args[2];
        int port = int.Parse(args[3]);
        string dir = Path.Combine(Environment.GetEnvironmentVariable("PQCC_CERTS") ?? "/certs/out", variant);

        X509Certificate2 root;
        try { root = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(dir, "root.crt")); }
        catch (Exception e) { return Fail("parse root certificate", e); }

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = host,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            RemoteCertificateValidationCallback = (_, cert, chain, errors) => Validate(root, cert, chain, errors),
        };
        if (mode == "mtls")
        {
            try
            {
                var leaf = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(dir, "client.p12"), P12Pass);
                if (!leaf.HasPrivateKey)
                    throw new CryptographicException("client.p12 loaded without a private key");
                var intermediate = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(dir, "int.crt"));
                Console.WriteLine($"Client certificate: {leaf.Subject} ({leaf.PublicKey.Oid.FriendlyName ?? leaf.PublicKey.Oid.Value})");
                options.ClientCertificateContext = SslStreamCertificateContext.Create(
                    leaf, new X509Certificate2Collection(intermediate), offline: true);
            }
            catch (Exception e) { return Fail("load client certificate/key", e); }
        }

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using var tcp = new TcpClient();
            tcp.ConnectAsync(host, port, cts.Token).AsTask().GetAwaiter().GetResult();
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            ssl.AuthenticateAsClientAsync(options, cts.Token).GetAwaiter().GetResult();
            Console.WriteLine($"Protocol version: {TlsName(ssl.SslProtocol)}");
            Console.WriteLine($"Cipher: {ssl.NegotiatedCipherSuite}");

            ssl.Write(Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n"));
            using var reader = new StreamReader(ssl, Encoding.ASCII);
            string status = reader.ReadLine() ?? "";
            Console.WriteLine($"Response: {status}");
            return status.StartsWith("HTTP/1.0 200") ? 0 : Fail("http", new Exception($"unexpected response: {status}"));
        }
        catch (OperationCanceledException) { return Fail("handshake", new TimeoutException("timed out after 20s")); }
        catch (Exception e) { return Fail("handshake", e); }
    }

    static bool Validate(X509Certificate2 root, X509Certificate cert, X509Chain platformChain, SslPolicyErrors errors)
    {
        Console.WriteLine($"Platform policy errors: {errors}");
        if (cert is null) { Console.WriteLine("verify error: server sent no certificate"); return false; }
        if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
        {
            Console.WriteLine("verify error: hostname mismatch");
            return false;
        }
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthOid));
        // Intermediates the server sent (the platform puts them in its chain's ExtraStore).
        if (platformChain is not null)
            chain.ChainPolicy.ExtraStore.AddRange(platformChain.ChainPolicy.ExtraStore);
        var leaf = cert as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
        bool ok = chain.Build(leaf);
        foreach (var el in chain.ChainElements)
        {
            string status = string.Join(", ", el.ChainElementStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}"));
            Console.WriteLine($"  chain: {el.Certificate.Subject} [{el.Certificate.SignatureAlgorithm.FriendlyName ?? el.Certificate.SignatureAlgorithm.Value}]" +
                              (status.Length > 0 ? $" -> {status}" : ""));
        }
        if (!ok)
            Console.WriteLine("verify error: " + string.Join("; ", chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}")));
        return ok;
    }

    static string TlsName(SslProtocols p) => p switch
    {
        SslProtocols.Tls13 => "TLSv1.3",
        SslProtocols.Tls12 => "TLSv1.2",
        _ => p.ToString(),
    };

    static string Version()
    {
        string backend;
        if (OperatingSystem.IsLinux())
        {
            long v = SafeEvpPKeyHandle.OpenSslVersion;  // 0xMNN00PP0
            backend = $"OpenSSL {(v >> 28) & 0xF}.{(v >> 20) & 0xFF}.{(v >> 4) & 0xFF}";
        }
        else if (OperatingSystem.IsWindows()) backend = "SChannel";
        else if (OperatingSystem.IsMacOS()) backend = UsesNetworkFramework() ? "Apple Network.framework" : "Apple SecureTransport";
        else backend = "unknown";
        return $"{RuntimeInformation.FrameworkDescription} ({RuntimeInformation.RuntimeIdentifier}; {RuntimeInformation.OSDescription.Trim()}; TLS: {backend})";
    }

    // .NET 10 on macOS uses SecureTransport unless this opt-in switch is set (same lookup order
    // as System.Net.Security: AppContext switch, then environment variable).
    static bool UsesNetworkFramework() =>
        AppContext.TryGetSwitch("System.Net.Security.UseNetworkFramework", out bool on)
            ? on
            : Environment.GetEnvironmentVariable("DOTNET_SYSTEM_NET_SECURITY_USENETWORKFRAMEWORK") is "1" or "true";

    static int Fail(string stage, Exception e)
    {
        Console.Error.WriteLine($"stage failed: {stage}");
        // Exception chain, one message per line (the classifier matches on these).
        for (var x = e; x is not null; x = x.InnerException)
            Console.Error.WriteLine($"{x.GetType().FullName}: {x.Message}");
        return 1;
    }
}
