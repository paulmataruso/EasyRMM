using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class NewerLinuxReleases : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "os_lifecycle_entries",
                columns: new[] { "id", "build_number", "edition_group", "end_of_servicing", "esu_end_date", "notes", "product", "version_label" },
                values: new object[,]
                {
                    { new Guid("19aff03a-9ee7-6c23-dc52-9cb2c78fcaf1"), 44, "Any", new DateOnly(2027, 5, 19), null, null, "Fedora", "44" },
                    { new Guid("4e7b46d0-d0ea-5845-4460-a1f05cc31da5"), 10, "Any", new DateOnly(2030, 5, 31), null, null, "CentOS Stream", "10" },
                    { new Guid("4f178184-5e0b-fc2b-0a47-c949f84868d0"), 9, "Any", new DateOnly(2027, 5, 31), null, null, "CentOS Stream", "9" },
                    { new Guid("666b087d-3db8-00e4-a3af-2cd893a7dbcf"), 10, "Any", new DateOnly(2035, 6, 30), null, "End of Premier Support (Oracle Lifetime Support Policy: June 2035).", "Oracle Linux", "10" },
                    { new Guid("e98444e6-145c-af34-ecd3-f0ada06071f7"), 45, "Any", new DateOnly(2027, 12, 8), null, null, "Fedora", "45" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("19aff03a-9ee7-6c23-dc52-9cb2c78fcaf1"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("4e7b46d0-d0ea-5845-4460-a1f05cc31da5"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("4f178184-5e0b-fc2b-0a47-c949f84868d0"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("666b087d-3db8-00e4-a3af-2cd893a7dbcf"));

            migrationBuilder.DeleteData(
                table: "os_lifecycle_entries",
                keyColumn: "id",
                keyValue: new Guid("e98444e6-145c-af34-ecd3-f0ada06071f7"));
        }
    }
}
