using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class PreDownload : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "pre_download_hours",
                table: "policies",
                type: "integer",
                nullable: true);

            // The global policy defines every value: downloads ahead of the window start off.
            migrationBuilder.Sql("UPDATE policies SET pre_download_hours = 0 WHERE scope = 'Global' AND pre_download_hours IS NULL;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "pre_download_hours",
                table: "policies");
        }
    }
}
