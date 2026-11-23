using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <summary>ADR-0069: the diagnostics a repair or a log collection returns, kept apart from the job's message.</summary>
    [DbContext(typeof(EasyPatchDbContext))]
    [Migration("20261123120000_JobDiagnostics")]
    public partial class JobDiagnosticsColumn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "diagnostics",
                table: "jobs",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "diagnostics",
                table: "jobs");
        }
    }
}
