using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class RolloutGuard : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "update_holds",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    update_guid = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: true),
                    source = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: false),
                    failed_endpoints = table.Column<int>(type: "integer", nullable: true),
                    attempted_endpoints = table.Column<int>(type: "integer", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    released_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    released_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    released_by = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_update_holds", x => x.id);
                    table.ForeignKey(
                        name: "FK_update_holds_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_update_holds_organization_id",
                table: "update_holds",
                column: "organization_id");

            migrationBuilder.CreateIndex(
                name: "IX_update_holds_released_at",
                table: "update_holds",
                column: "released_at");

            migrationBuilder.CreateIndex(
                name: "IX_update_holds_update_guid",
                table: "update_holds",
                column: "update_guid",
                unique: true,
                filter: "organization_id IS NULL AND released_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "IX_update_holds_update_guid_organization_id",
                table: "update_holds",
                columns: new[] { "update_guid", "organization_id" },
                unique: true,
                filter: "organization_id IS NOT NULL AND released_at IS NULL");

            // Default alert rule 9 (see AlertRuleCatalog.Defaults).
            migrationBuilder.Sql("""
                INSERT INTO alert_rules (id, name, type, enabled, severity, threshold, organization_id, tag_id, channel_ids, notify_on_resolve, renotify_hours, created_at, updated_at)
                VALUES ('7c3e1a52-6f0e-4d7b-9a01-000000000009', 'Update on hold', 'UpdateHeld', TRUE, 'Warning', NULL, NULL, NULL, '{}'::uuid[], FALSE, 0, now(), now())
                ON CONFLICT (id) DO NOTHING;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DELETE FROM alerts WHERE rule_type = 'UpdateHeld';");
            migrationBuilder.Sql("DELETE FROM alert_rules WHERE type = 'UpdateHeld';");

            migrationBuilder.DropTable(
                name: "update_holds");
        }
    }
}
