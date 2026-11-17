using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using EasyPatch.Core.Entities;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using MimeKit;

namespace EasyPatch.Infrastructure.Notifications;

/// <summary>Encrypts notification secrets (SMTP password, webhook URLs, signing keys) with ASP.NET Data Protection. The API
/// and the worker share the key ring on the <c>dpkeys</c> volume.</summary>
public sealed class NotificationSecrets(IDataProtectionProvider provider, IConfiguration configuration)
{
    private const string Purpose = "EasyPatch.Notifications.v1";

    public string Protect(string plaintext) => provider.CreateProtector(Purpose).Protect(plaintext);

    public string Unprotect(string protectedText)
    {
        try
        {
            return provider.CreateProtector(Purpose).Unprotect(protectedText);
        }
        catch (CryptographicException)
        {
            // The key ring may have changed since this process cached it (the API created a new key): read it again.
            var keysPath = configuration["EasyPatch:DataProtectionKeysPath"] ?? "/app/keys";
            try
            {
                var fresh = DataProtectionProvider.Create(new DirectoryInfo(keysPath), b => b.SetApplicationName("EasyPatch"));
                return fresh.CreateProtector(Purpose).Unprotect(protectedText);
            }
            catch (CryptographicException)
            {
                throw new NotificationException(
                    "A stored notification secret cannot be decrypted. The API and the worker must share the data protection keys (dpkeys volume); " +
                    "enter the secret again if the keys were lost.");
            }
        }
    }

    /// <summary>A random secret for signing generic webhooks (shown to the administrator once).</summary>
    public static string NewSigningSecret() => Base64Url(RandomNumberGenerator.GetBytes(32));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>A delivery failure with a message that is safe to store and show (no URLs, tokens or passwords).</summary>
public class NotificationException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>A file attached to an email (monthly report PDFs).</summary>
public sealed record EmailAttachment(string FileName, string ContentType, byte[] Content);

/// <summary>Sends email and webhook requests. Replaced by a fake in tests.</summary>
public interface INotificationTransport
{
    Task SendEmailAsync(NotificationSettingsRow smtp, string? password, IReadOnlyList<string> recipients, string subject, string text, string html,
        IReadOnlyList<EmailAttachment>? attachments, CancellationToken ct);

    Task PostWebhookAsync(Uri url, string body, IReadOnlyDictionary<string, string> headers, bool allowPrivateNetworks, CancellationToken ct);
}

public sealed partial class NotificationTransport(IHttpClientFactory httpClients) : INotificationTransport
{
    public const string WebhookClient = "easypatch-webhooks";
    public const int MaxResponseBytes = 64 * 1024;

    public async Task SendEmailAsync(NotificationSettingsRow smtp, string? password, IReadOnlyList<string> recipients, string subject, string text,
        string html, IReadOnlyList<EmailAttachment>? attachments, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(smtp);
        ArgumentNullException.ThrowIfNull(recipients);
        if (string.IsNullOrWhiteSpace(smtp.SmtpHost) || string.IsNullOrWhiteSpace(smtp.FromAddress))
        {
            throw new NotificationException("SMTP is not configured (Settings → Notifications).");
        }

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(string.IsNullOrWhiteSpace(smtp.FromName) ? "EasyPatch" : smtp.FromName, smtp.FromAddress));
        foreach (var r in recipients)
        {
            message.To.Add(MailboxAddress.Parse(r));
        }

        message.Subject = subject;
        var body = new BodyBuilder { TextBody = text, HtmlBody = html };
        foreach (var attachment in attachments ?? [])
        {
            body.Attachments.Add(attachment.FileName, attachment.Content, ContentType.Parse(attachment.ContentType));
        }

        message.Body = body.ToMessageBody();

        using var client = new SmtpClient { Timeout = 30_000 };
        if (smtp.SmtpSkipCertificateValidation && smtp.SmtpSecurity != SmtpSecurity.None)
        {
            // The administrator's explicit choice (Settings → Notifications), e.g. for an internal relay with a self-signed
            // certificate: the connection stays encrypted, but the server's identity is not verified.
#pragma warning disable CA5359 // Opt-in by a super administrator, off by default, audited and shown with a warning in the console.
            client.ServerCertificateValidationCallback = static (_, _, _, _) => true;
#pragma warning restore CA5359
            client.CheckCertificateRevocation = false;
        }

        var security = smtp.SmtpSecurity switch
        {
            SmtpSecurity.SslOnConnect => SecureSocketOptions.SslOnConnect,
            SmtpSecurity.None => SecureSocketOptions.None,
            _ => SecureSocketOptions.StartTls,
        };
        try
        {
            await client.ConnectAsync(smtp.SmtpHost, smtp.SmtpPort, security, ct);
            if (!string.IsNullOrEmpty(smtp.SmtpUsername))
            {
                await client.AuthenticateAsync(smtp.SmtpUsername, password ?? string.Empty, ct);
            }

            await client.SendAsync(message, ct);
            await client.DisconnectAsync(true, ct);
        }
        catch (AuthenticationException ex)
        {
            throw new NotificationException("The SMTP server refused the user name or password.", ex);
        }
        catch (SslHandshakeException ex)
        {
            throw new NotificationException("TLS connection to the SMTP server failed (certificate not trusted or TLS not offered).", ex);
        }
        catch (SmtpCommandException ex)
        {
            throw new NotificationException($"The SMTP server rejected the message ({(int)ex.StatusCode}): {Clip(ex.Message)}", ex);
        }
        catch (SmtpProtocolException ex)
        {
            throw new NotificationException($"SMTP protocol error: {Clip(ex.Message)}", ex);
        }
        catch (SocketException ex)
        {
            throw new NotificationException($"Cannot connect to the SMTP server {smtp.SmtpHost}:{smtp.SmtpPort} ({ex.SocketErrorCode}).", ex);
        }
        catch (IOException ex)
        {
            throw new NotificationException("The connection to the SMTP server was interrupted.", ex);
        }
        catch (TimeoutException ex)
        {
            throw new NotificationException("The SMTP server did not answer in time.", ex);
        }
    }

    public async Task PostWebhookAsync(Uri url, string body, IReadOnlyDictionary<string, string> headers, bool allowPrivateNetworks, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentNullException.ThrowIfNull(headers);
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        request.Options.Set(WebhookHttp.AllowPrivateOption, allowPrivateNetworks);
        foreach (var (name, value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        var client = httpClients.CreateClient(WebhookClient);
        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        }
        catch (HttpRequestException ex) when (ex.InnerException is WebhookBlockedException blocked)
        {
            throw new NotificationException(blocked.Message, ex);
        }
        catch (HttpRequestException ex)
        {
            throw new NotificationException($"Cannot reach {url.Host} ({ex.HttpRequestError}).", ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new NotificationException($"{url.Host} did not answer in time.", ex);
        }

        using (response)
        {
            if ((int)response.StatusCode is >= 300 and < 400)
            {
                throw new NotificationException($"{url.Host} answered with a redirect ({(int)response.StatusCode}); redirects are not followed.");
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new NotificationException($"{url.Host} answered HTTP {(int)response.StatusCode}.");
            }

            // Drain a bounded amount so the connection can be reused; the content is not used.
            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[8192];
            var total = 0;
            int read;
            while (total < MaxResponseBytes && (read = await stream.ReadAsync(buffer, ct)) > 0)
            {
                total += read;
            }
        }
    }

    private static string Clip(string s)
    {
        var cleaned = UrlPattern().Replace(s, "[url]");
        return cleaned.Length > 200 ? cleaned[..200] : cleaned;
    }

    [GeneratedRegex(@"https?://\S+", RegexOptions.IgnoreCase)]
    private static partial Regex UrlPattern();
}

public sealed class WebhookBlockedException(string message) : Exception(message);

/// <summary>HTTP handler settings for webhooks: no proxy, no redirects, short timeouts, and the SSRF address check on the
/// address actually connected to.</summary>
public static class WebhookHttp
{
    public static readonly HttpRequestOptionsKey<bool> AllowPrivateOption = new("easypatch.allowPrivateNetworks");
    private static readonly Lazy<IReadOnlyList<(IPAddress Network, int Prefix)>> OwnNetworks = new(WebhookAddressPolicy.LocalNetworks);

    public static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectCallback = ConnectAsync,
    };

    private static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var allowPrivate = context.InitialRequestMessage.Options.TryGetValue(AllowPrivateOption, out var allow) && allow;
        var host = context.DnsEndPoint.Host;
        var addresses = IPAddress.TryParse(host, out var literal) ? [literal] : await Dns.GetHostAddressesAsync(host, ct);
        string? reason = null;
        SocketException? lastError = null;
        foreach (var address in addresses)
        {
            var refused = WebhookAddressPolicy.Check(address, allowPrivate, OwnNetworks.Value);
            if (refused is not null)
            {
                reason = refused;
                continue;
            }

            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, context.DnsEndPoint.Port), ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                lastError = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        if (lastError is not null)
        {
            throw lastError;
        }

        throw new WebhookBlockedException(addresses.Length == 0
            ? $"{host} does not resolve to an address."
            : $"Webhook to {host} refused: {reason}.");
    }
}
