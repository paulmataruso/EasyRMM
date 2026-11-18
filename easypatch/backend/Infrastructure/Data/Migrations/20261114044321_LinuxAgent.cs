using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class LinuxAgent : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<List<string>>(
                name: "advisories",
                table: "updates",
                type: "text[]",
                nullable: false,
                defaultValueSql: "'{}'::text[]");

            migrationBuilder.AddColumn<string>(
                name: "package_architecture",
                table: "updates",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "package_name",
                table: "updates",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "package_repository",
                table: "updates",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "package_version",
                table: "updates",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "agent_package_format",
                table: "endpoints",
                type: "character varying(8)",
                maxLength: 8,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "kernel_version",
                table: "endpoints",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "key_protection",
                table: "endpoints",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "os_id",
                table: "endpoints",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "package_manager",
                table: "endpoints",
                type: "character varying(16)",
                maxLength: 16,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "platform",
                table: "endpoints",
                type: "character varying(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "Windows");

            migrationBuilder.AddColumn<string>(
                name: "installed_version",
                table: "endpoint_updates",
                type: "character varying(255)",
                maxLength: 255,
                nullable: true);

            migrationBuilder.InsertData(
                table: "os_lifecycle_entries",
                columns: new[] { "id", "build_number", "edition_group", "end_of_servicing", "esu_end_date", "notes", "product", "version_label" },
                values: new object[,]
                {
                    { new Guid("0c96e30c-cd3e-64c4-f2e1-5f30db5d057c"), 10, "Any", new DateOnly(2035, 5, 31), null, "End of maintenance support; Extended Life Cycle Support is sold separately.", "Red Hat Enterprise Linux", "10" },
                    { new Guid("22bb00f0-690e-326b-23d4-8705f6afc9fe"), 11, "Any", new DateOnly(2026, 8, 31), null, "Regular security support ended 2024-08-14; Debian LTS until 2026-08-31.", "Debian", "11 (bullseye)" },
                    { new Guid("31ccfcc2-4649-9a83-2ffe-c7bb0fbcb5d1"), 2004, "LTS", new DateOnly(2025, 5, 31), new DateOnly(2030, 4, 30), "ESU: Ubuntu Pro (ESM) until 2030-04.", "Ubuntu", "20.04 LTS" },
                    { new Guid("38cbbda1-7af1-08a0-6f0b-debd24f91501"), 10, "Any", new DateOnly(2035, 5, 31), null, null, "AlmaLinux", "10" },
                    { new Guid("4a8e58e5-7f89-7930-9d07-f4ebc62cfd9c"), 8, "Any", new DateOnly(2029, 3, 1), null, null, "AlmaLinux", "8" },
                    { new Guid("4b34aad0-fc45-22de-2fc5-ffba17777891"), 9, "Any", new DateOnly(2032, 5, 31), null, null, "Rocky Linux", "9" },
                    { new Guid("4b5263fb-8671-2767-fc78-2a9ec3658c1b"), 12, "Any", new DateOnly(2028, 6, 30), null, "Regular security support until 2026-06-10; Debian LTS until 2028-06-30.", "Debian", "12 (bookworm)" },
                    { new Guid("5ddeeda8-5605-7e21-d062-5d125f6fbb41"), 10, "Any", new DateOnly(2035, 5, 31), null, null, "Rocky Linux", "10" },
                    { new Guid("717490f1-3a05-f959-4061-5f0f815f77d2"), 9, "Any", new DateOnly(2032, 6, 30), null, "End of Premier Support.", "Oracle Linux", "9" },
                    { new Guid("71f39a06-bc62-98dc-9775-f8083fa3057c"), 9, "Any", new DateOnly(2032, 5, 31), null, null, "AlmaLinux", "9" },
                    { new Guid("7aa9d747-24c3-0ed2-9acb-c983ee112d83"), 8, "Any", new DateOnly(2029, 5, 31), null, "End of maintenance support; Extended Life Cycle Support is sold separately.", "Red Hat Enterprise Linux", "8" },
                    { new Guid("84ef8613-29a0-1481-7ba3-a323a4b8f2fc"), 2404, "LTS", new DateOnly(2029, 5, 31), new DateOnly(2034, 4, 30), "ESU: Ubuntu Pro (ESM) until 2034-04.", "Ubuntu", "24.04 LTS" },
                    { new Guid("a0ccec08-1482-08c1-7778-1c9b63dcee85"), 13, "Any", new DateOnly(2030, 6, 30), null, "Regular security support until about 2028-08; Debian LTS until 2030-06-30.", "Debian", "13 (trixie)" },
                    { new Guid("ac90225a-f807-a142-01ca-c25dd3f8b803"), 8, "Any", new DateOnly(2029, 7, 31), null, "End of Premier Support.", "Oracle Linux", "8" },
                    { new Guid("bb7f3dc0-8931-aa7b-3574-08955eaf1154"), 2604, "LTS", new DateOnly(2031, 5, 31), new DateOnly(2036, 4, 30), "ESU: Ubuntu Pro (ESM) until 2036-04.", "Ubuntu", "26.04 LTS" },
                    { new Guid("c349ec45-8a97-feb3-8289-4072a8b49447"), 2204, "LTS", new DateOnly(2027, 6, 30), new DateOnly(2032, 4, 30), "ESU: Ubuntu Pro (ESM) until 2032-04.", "Ubuntu", "22.04 LTS" },
                    { new Guid("f2725818-966a-1354-9c18-be7fee3b1797"), 8, "Any", new DateOnly(2029, 5, 31), null, null, "Rocky Linux", "8" },
                    { new Guid("f626d641-5329-d4fd-77b0-063a8afd630e"), 9, "Any", new DateOnly(2032, 5, 31), null, "End of maintenance support; Extended Life Cycle Support is sold separately.", "Red Hat Enterprise Linux", "9" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_endpoints_platform",
                table: "endpoints",
                column: "platform");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_endpoints_platform",
                table: "endpoints");

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("0c96e30c-cd3e-64c4-f2e1-5f30db5d057c"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("22bb00f0-690e-326b-23d4-8705f6afc9fe"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("31ccfcc2-4649-9a83-2ffe-c7bb0fbcb5d1"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("38cbbda1-7af1-08a0-6f0b-debd24f91501"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("4a8e58e5-7f89-7930-9d07-f4ebc62cfd9c"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("4b34aad0-fc45-22de-2fc5-ffba17777891"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("4b5263fb-8671-2767-fc78-2a9ec3658c1b"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("5ddeeda8-5605-7e21-d062-5d125f6fbb41"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("717490f1-3a05-f959-4061-5f0f815f77d2"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("71f39a06-bc62-98dc-9775-f8083fa3057c"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("7aa9d747-24c3-0ed2-9acb-c983ee112d83"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("84ef8613-29a0-1481-7ba3-a323a4b8f2fc"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("a0ccec08-1482-08c1-7778-1c9b63dcee85"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("ac90225a-f807-a142-01ca-c25dd3f8b803"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("bb7f3dc0-8931-aa7b-3574-08955eaf1154"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("c349ec45-8a97-feb3-8289-4072a8b49447"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("f2725818-966a-1354-9c18-be7fee3b1797"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("f626d641-5329-d4fd-77b0-063a8afd630e"));

            migrationBuilder.DropColumn(
                name: "advisories",
                table: "updates");

            migrationBuilder.DropColumn(
                name: "package_architecture",
                table: "updates");

            migrationBuilder.DropColumn(
                name: "package_name",
                table: "updates");

            migrationBuilder.DropColumn(
                name: "package_repository",
                table: "updates");

            migrationBuilder.DropColumn(
                name: "package_version",
                table: "updates");

            migrationBuilder.DropColumn(
                name: "agent_package_format",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "kernel_version",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "key_protection",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "os_id",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "package_manager",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "platform",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "installed_version",
                table: "endpoint_updates");
        }
    }
}
