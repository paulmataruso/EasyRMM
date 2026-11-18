namespace EasyPatch.Infrastructure.Services;

/// <summary>An expected, user-facing failure. The API maps it to an RFC 9457 problem response.</summary>
public sealed class AppException : Exception
{
    public AppException(int statusCode, string code, string message, IReadOnlyDictionary<string, object?>? extensions = null)
        : base(message)
    {
        StatusCode = statusCode;
        Code = code;
        Extensions = extensions ?? new Dictionary<string, object?>();
    }

    public AppException()
        : this(500, "error", "An error occurred.")
    {
    }

    public AppException(string message)
        : this(400, "bad_request", message)
    {
    }

    public AppException(string message, Exception innerException)
        : base(message, innerException)
    {
        StatusCode = 500;
        Code = "error";
        Extensions = new Dictionary<string, object?>();
    }

    public int StatusCode { get; }
    public string Code { get; }
    public IReadOnlyDictionary<string, object?> Extensions { get; }

    public static AppException NotFound(string what) => new(404, "not_found", $"{what} was not found.");

    public static AppException BadRequest(string message, string code = "bad_request") => new(400, code, message);

    public static AppException Conflict(string message, string code = "conflict", IReadOnlyDictionary<string, object?>? extensions = null) =>
        new(409, code, message, extensions);

    public static AppException Forbidden(string message = "You do not have permission to perform this action.") =>
        new(403, "forbidden", message);

    public static AppException Unauthorized(string code, string message, IReadOnlyDictionary<string, object?>? extensions = null) =>
        new(401, code, message, extensions);
}
