using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace EasyPatch.Infrastructure.Data;

/// <summary>Used only by <c>dotnet ef</c> to create migrations. No database connection is opened.</summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<EasyPatchDbContext>
{
    public EasyPatchDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<EasyPatchDbContext>()
            .UseNpgsql("Host=localhost;Database=easypatch_design;Username=design")
            .Options;
        return new EasyPatchDbContext(options);
    }
}
