using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class ApplicationUpdates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "application_updates",
                table: "policies",
                type: "jsonb",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "application_scan_at",
                table: "endpoints",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "application_scan_error",
                table: "endpoints",
                type: "character varying(1000)",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "winget_version",
                table: "endpoints",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "application_updates",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "application_scan_at",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "application_scan_error",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "winget_version",
                table: "endpoints");
        }
    }
}
