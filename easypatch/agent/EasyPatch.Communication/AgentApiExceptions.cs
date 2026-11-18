using System.Net;

namespace EasyPatch.Communication;

/// <summary>Base type for every failure surfaced by <see cref="AgentApiClient"/>.</summary>
public abstract class AgentApiException : Exception
{
    protected AgentApiException(string message, HttpStatusCode? statusCode, string? errorCode, Exception? inner = null)
        : base(message, inner)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }

    /// <summary>HTTP status, or null when no response was received.</summary>
    public HttpStatusCode? StatusCode { get; }

    /// <summary>Machine-readable ProblemDetails "code" (see <c>AgentErrorCodes</c>), when supplied.</summary>
    public string? ErrorCode { get; }
}

/// <summary>Network failure, timeout, 408, 429 or 5xx. Safe to retry later with backoff.</summary>
public sealed class AgentTransientException : AgentApiException
{
    public AgentTransientException(string message, HttpStatusCode? statusCode, string? errorCode, TimeSpan? retryAfter, Exception? inner = null)
        : base(message, statusCode, errorCode, inner)
    {
        RetryAfter = retryAfter;
    }

    /// <summary>Server-requested delay (Retry-After), if any.</summary>
    public TimeSpan? RetryAfter { get; }
}

/// <summary>The server rejected the agent's identity.</summary>
public sealed class AgentAuthException : AgentApiException
{
    public AgentAuthException(string message, HttpStatusCode? statusCode, string? errorCode, bool isFatal)
        : base(message, statusCode, errorCode)
    {
        IsFatal = isFatal;
    }

    /// <summary>
    /// True when the credential can never work again (revoked, expired, unknown, endpoint revoked):
    /// the agent must stop normal operation and wait for re-enrollment.
    /// </summary>
    public bool IsFatal { get; }
}

/// <summary>The server understood the request and refused it (4xx other than auth), e.g. job_cancelled.</summary>
public sealed class AgentRejectedException : AgentApiException
{
    public AgentRejectedException(string message, HttpStatusCode statusCode, string? errorCode)
        : base(message, statusCode, errorCode)
    {
    }
}
