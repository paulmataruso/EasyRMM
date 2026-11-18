using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class TagsAndRolloutDelay : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "install_delay_days",
                table: "policies",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "security_install_delay_days",
                table: "policies",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "tag_id",
                table: "policies",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "missing_deferred_count",
                table: "endpoints",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "deferred_until",
                table: "endpoint_updates",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "delay_basis_at",
                table: "endpoint_updates",
                type: "timestamp with time zone",
                nullable: true);

            // Existing rows start their (optional) rollout delay when they were first detected.
            migrationBuilder.Sql("UPDATE endpoint_updates SET delay_basis_at = first_detected_at WHERE delay_basis_at IS NULL;");

            migrationBuilder.CreateTable(
                name: "tags",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    color = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    priority = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tags", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "endpoint_tags",
                columns: table => new
                {
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    tag_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_endpoint_tags", x => new { x.endpoint_id, x.tag_id });
                    table.ForeignKey(
                        name: "FK_endpoint_tags_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "endpoints",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_endpoint_tags_tags_tag_id",
                        column: x => x.tag_id,
                        principalTable: "tags",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_policies_tag_id",
                table: "policies",
                column: "tag_id",
                unique: true,
                filter: "scope = 'Tag'");

            migrationBuilder.CreateIndex(
                name: "IX_endpoint_updates_deferred_until",
                table: "endpoint_updates",
                column: "deferred_until",
                filter: "deferred_until IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_endpoint_tags_tag_id",
                table: "endpoint_tags",
                column: "tag_id");

            migrationBuilder.CreateIndex(
                name: "IX_tags_name",
                table: "tags",
                column: "name",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_policies_tags_tag_id",
                table: "policies",
                column: "tag_id",
                principalTable: "tags",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_policies_tags_tag_id",
                table: "policies");

            migrationBuilder.DropTable(
                name: "endpoint_tags");

            migrationBuilder.DropTable(
                name: "tags");

            migrationBuilder.DropIndex(
                name: "IX_policies_tag_id",
                table: "policies");

            migrationBuilder.DropIndex(
                name: "IX_endpoint_updates_deferred_until",
                table: "endpoint_updates");

            migrationBuilder.DropColumn(
                name: "install_delay_days",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "security_install_delay_days",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "tag_id",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "missing_deferred_count",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "deferred_until",
                table: "endpoint_updates");

            migrationBuilder.DropColumn(
                name: "delay_basis_at",
                table: "endpoint_updates");
        }
    }
}
