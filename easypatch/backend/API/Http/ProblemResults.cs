using System.Text.Json;
using EasyPatch.Infrastructure.Services;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;

namespace EasyPatch.Api;

/// <summary>Writes RFC 9457 problem details with a machine-readable <c>code</c> and the correlation ID.</summary>
public static class ProblemResults
{
    public static async Task WriteAsync(HttpContext context, int status, string code, string detail, IReadOnlyDictionary<string, object?>? extensions = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Response.HasStarted)
        {
            return;
        }

        var problem = Create(context, status, code, detail, extensions);
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/problem+json";
        context.Response.Headers.CacheControl = "no-store";
        var options = context.RequestServices.GetService<IOptions<Microsoft.AspNetCore.Http.Json.JsonOptions>>()?.Value.SerializerOptions ?? JsonSerializerOptions.Web;
        await JsonSerializer.SerializeAsync(context.Response.Body, problem, options, context.RequestAborted);
    }

    public static ProblemDetails Create(HttpContext context, int status, string code, string detail, IReadOnlyDictionary<string, object?>? extensions = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        var problem = new ProblemDetails
        {
            Status = status,
            Title = Title(status),
            Detail = detail,
            Type = "about:blank",
            Instance = context.Request.Path,
        };
        problem.Extensions["code"] = code;
        problem.Extensions["correlationId"] = context.TraceIdentifier;
        if (extensions is not null)
        {
            foreach (var (k, v) in extensions)
            {
                problem.Extensions[k] = v;
            }
        }

        return problem;
    }

    public static string Title(int status) => status switch
    {
        400 => "Bad request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not found",
        409 => "Conflict",
        413 => "Payload too large",
        415 => "Unsupported media type",
        422 => "Unprocessable content",
        429 => "Too many requests",
        503 => "Service unavailable",
        _ => status >= 500 ? "Server error" : "Error",
    };
}

/// <summary>Maps exceptions to problem details. Internal errors never leak exception details to clients.</summary>
public sealed class EasyPatchExceptionHandler(ILogger<EasyPatchExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        switch (exception)
        {
            case AppException app:
                await ProblemResults.WriteAsync(httpContext, app.StatusCode, app.Code, app.Message, app.Extensions);
                return true;
            case BadHttpRequestException bad:
                await ProblemResults.WriteAsync(httpContext, bad.StatusCode, bad.StatusCode == 413 ? "payload_too_large" : "bad_request",
                    bad.StatusCode == 413 ? "The request body is too large."
                    : bad.InnerException is JsonException json ? "The request body is not valid: " + Truncate(json.Message, 300)
                    : "The request could not be read. Check the JSON body and content type.");
                return true;
            case JsonException:
                await ProblemResults.WriteAsync(httpContext, 400, "invalid_json", "The request body is not valid JSON for this operation.");
                return true;
            case DbUpdateConcurrencyException:
                await ProblemResults.WriteAsync(httpContext, 409, "concurrency_conflict", "The record was changed by another request. Reload and try again.");
                return true;
            case DbUpdateException { InnerException: PostgresException { SqlState: PostgresErrorCodes.UniqueViolation } }:
                await ProblemResults.WriteAsync(httpContext, 409, "conflict", "A record with the same unique value already exists.");
                return true;
            case OperationCanceledException when httpContext.RequestAborted.IsCancellationRequested:
                return true;
            default:
                logger.LogError(exception, "Unhandled exception for {Method} {Path}", httpContext.Request.Method, httpContext.Request.Path);
                await ProblemResults.WriteAsync(httpContext, 500, "internal_error",
                    "An unexpected error occurred. Quote the correlation ID when reporting this problem.");
                return true;
        }
    }

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}

/// <summary>Accepts a safe <c>X-Correlation-ID</c> or uses the generated trace identifier, and echoes it.</summary>
public sealed class CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
{
    public const string HeaderName = "X-Correlation-ID";

    public async Task InvokeAsync(HttpContext context)
    {
        var incoming = context.Request.Headers[HeaderName].ToString();
        if (incoming.Length is > 0 and <= 64 && incoming.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'))
        {
            context.TraceIdentifier = incoming;
        }

        context.Response.OnStarting(() =>
        {
            context.Response.Headers[HeaderName] = context.TraceIdentifier;
            return Task.CompletedTask;
        });
        using (logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = context.TraceIdentifier }))
        {
            await next(context);
        }
    }
}
