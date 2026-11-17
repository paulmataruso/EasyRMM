using System.Text.Json;
using EasyPatch.Contracts.Json;
using EasyPatch.Core.Domain;
using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;

namespace EasyPatch.Infrastructure.Services;

public sealed class SettingsService(EasyPatchDbContext db, IMemoryCache cache, TimeProvider clock)
{
    private const string CacheKey = "server-settings";

    public async Task<ServerSettings> GetAsync(CancellationToken ct = default)
    {
        if (cache.TryGetValue(CacheKey, out ServerSettings? cached) && cached is not null)
        {
            return cached;
        }

        var row = await db.ServerSettings.AsNoTracking().FirstOrDefaultAsync(r => r.Id == 1, ct);
        var settings = row is null ? new ServerSettings() : Parse(row.Data);
        cache.Set(CacheKey, settings, TimeSpan.FromSeconds(15));
        return settings;
    }

    public async Task<ServerSettings> UpdateAsync(ServerSettings settings, Guid? userId, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var errors = settings.Validate();
        if (errors.Count > 0)
        {
            throw AppException.BadRequest(string.Join(" ", errors), "validation_failed");
        }

        var row = await db.ServerSettings.FirstOrDefaultAsync(r => r.Id == 1, ct);
        var json = JsonSerializer.Serialize(settings, ContractJson.Options);
        if (row is null)
        {
            db.ServerSettings.Add(new Core.Entities.ServerSettingsRow { Id = 1, Data = json, UpdatedAt = clock.GetUtcNow(), UpdatedByUserId = userId });
        }
        else
        {
            row.Data = json;
            row.UpdatedAt = clock.GetUtcNow();
            row.UpdatedByUserId = userId;
        }

        cache.Remove(CacheKey);
        return settings;
    }

    public void Invalidate() => cache.Remove(CacheKey);

    private static ServerSettings Parse(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<ServerSettings>(json, ContractJson.Options) ?? new ServerSettings();
        }
        catch (JsonException)
        {
            return new ServerSettings();
        }
    }
}
