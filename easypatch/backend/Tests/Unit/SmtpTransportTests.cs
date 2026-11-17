using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Notifications;
using Xunit;

namespace EasyPatch.Tests.Unit;

/// <summary>The real SMTP transport against a local server with a self-signed certificate.</summary>
public sealed class SmtpTransportTests
{
    private static NotificationSettingsRow Settings(int port, bool skipValidation) => new()
    {
        SmtpHost = "localhost",
        SmtpPort = port,
        SmtpSecurity = SmtpSecurity.SslOnConnect,
        SmtpSkipCertificateValidation = skipValidation,
        FromAddress = "easypatch@example.com",
    };

    private static Task SendAsync(NotificationSettingsRow smtp) =>
        new NotificationTransport(new NoHttpClients()).SendEmailAsync(smtp, null, ["admin@example.com"], "Test", "text", "<p>html</p>", null,
            TestContext.Current.CancellationToken);

    [Fact]
    public async Task An_untrusted_certificate_is_refused_unless_validation_is_skipped()
    {
        await using var server = new TlsSmtpStub();

        var refused = await Assert.ThrowsAsync<NotificationException>(() => SendAsync(Settings(server.Port, skipValidation: false)));
        Assert.StartsWith("TLS connection to the SMTP server failed", refused.Message, StringComparison.Ordinal);
        Assert.Empty(server.Messages);

        await SendAsync(Settings(server.Port, skipValidation: true));
        var message = Assert.Single(server.Messages);
        Assert.Contains("Subject: Test", message, StringComparison.Ordinal);
    }

    private sealed class NoHttpClients : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => throw new NotSupportedException();
    }

    /// <summary>A minimal SMTP server with TLS on connect and a self-signed certificate for localhost.</summary>
    private sealed class TlsSmtpStub : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly X509Certificate2 certificate;
        private readonly CancellationTokenSource stop = new();
        private readonly Task loop;

        public TlsSmtpStub()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
            certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
            listener.Start();
            loop = Task.Run(AcceptAsync);
        }

        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

        public ConcurrentQueue<string> Messages { get; } = new();

        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            listener.Stop();
            await loop;
            stop.Dispose();
            certificate.Dispose();
        }

        private async Task AcceptAsync()
        {
            while (!stop.IsCancellationRequested)
            {
                TcpClient tcp;
                try
                {
                    tcp = await listener.AcceptTcpClientAsync(stop.Token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
                {
                    return;
                }

                _ = Task.Run(() => HandleAsync(tcp));
            }
        }

        private async Task HandleAsync(TcpClient tcp)
        {
            using (tcp)
            {
                try
                {
                    await using var ssl = new SslStream(tcp.GetStream());
                    await ssl.AuthenticateAsServerAsync(certificate);
                    using var reader = new StreamReader(ssl, Encoding.ASCII, leaveOpen: true);
                    await using var writer = new StreamWriter(ssl, Encoding.ASCII, leaveOpen: true) { NewLine = "\r\n", AutoFlush = true };
                    await writer.WriteLineAsync("220 localhost ESMTP test");
                    while (await reader.ReadLineAsync() is { } line)
                    {
                        if (line.StartsWith("EHLO", StringComparison.OrdinalIgnoreCase))
                        {
                            await writer.WriteLineAsync("250 localhost");
                        }
                        else if (line.StartsWith("DATA", StringComparison.OrdinalIgnoreCase))
                        {
                            await writer.WriteLineAsync("354 Send the message");
                            var data = new StringBuilder();
                            while (await reader.ReadLineAsync() is { } dataLine && dataLine != ".")
                            {
                                data.Append(dataLine).Append('\n');
                            }

                            Messages.Enqueue(data.ToString());
                            await writer.WriteLineAsync("250 Queued");
                        }
                        else if (line.StartsWith("QUIT", StringComparison.OrdinalIgnoreCase))
                        {
                            await writer.WriteLineAsync("221 Bye");
                            return;
                        }
                        else
                        {
                            await writer.WriteLineAsync("250 OK");
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException or ObjectDisposedException)
                {
                    // The client refused the certificate and closed the connection.
                }
            }
        }
    }
}
