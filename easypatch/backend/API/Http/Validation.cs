using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api;

/// <summary>Collects field errors and throws one 400 <c>validation_failed</c> problem with an <c>errors</c> map.</summary>
public sealed class Validator
{
    private readonly Dictionary<string, List<string>> errors = new(StringComparer.Ordinal);

    public Validator Required(string field, string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            Add(field, "This field is required.");
        }
        else if (value.Length > maxLength)
        {
            Add(field, $"Must be at most {maxLength} characters.");
        }

        return this;
    }

    public Validator Optional(string field, string? value, int maxLength)
    {
        if (value is not null && value.Length > maxLength)
        {
            Add(field, $"Must be at most {maxLength} characters.");
        }

        return this;
    }

    public Validator Range(string field, int? value, int min, int max)
    {
        if (value is { } v && (v < min || v > max))
        {
            Add(field, $"Must be between {min} and {max}.");
        }

        return this;
    }

    public Validator Check(bool condition, string field, string message)
    {
        if (!condition)
        {
            Add(field, message);
        }

        return this;
    }

    public void Add(string field, string message)
    {
        if (!errors.TryGetValue(field, out var list))
        {
            errors[field] = list = [];
        }

        list.Add(message);
    }

    public void ThrowIfInvalid()
    {
        if (errors.Count > 0)
        {
            var first = errors.First();
            throw new AppException(400, "validation_failed", $"{first.Key}: {first.Value[0]}",
                new Dictionary<string, object?> { ["errors"] = errors.ToDictionary(e => e.Key, e => (object?)e.Value.ToArray()) });
        }
    }

    public static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public sealed record PageRequest(int Page, int PageSize)
{
    public const int MaxPageSize = 200;

    public static PageRequest From(int? page, int? pageSize) =>
        new(Math.Max(1, page ?? 1), Math.Clamp(pageSize ?? 50, 1, MaxPageSize));

    public int Skip => (Page - 1) * PageSize;
}

public static class PagingExtensions
{
    public static async Task<Contracts.PagedResult<T>> ToPagedAsync<T>(this IQueryable<T> query, PageRequest page, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(page);
        var total = await query.CountAsync(ct);
        var items = await query.Skip(page.Skip).Take(page.PageSize).ToListAsync(ct);
        return new Contracts.PagedResult<T>(items, page.Page, page.PageSize, total);
    }

    public static bool IsDescending(string? dir) => string.Equals(dir, "desc", StringComparison.OrdinalIgnoreCase);
}
