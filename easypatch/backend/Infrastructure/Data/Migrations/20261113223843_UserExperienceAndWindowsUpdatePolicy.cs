using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class UserExperienceAndWindowsUpdatePolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "endpoint_id",
                table: "policies",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "install_notifications_enabled",
                table: "policies",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "restart_schedule",
                table: "policies",
                type: "jsonb",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "tray_icon_enabled",
                table: "policies",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "windows_update",
                table: "policies",
                type: "jsonb",
                nullable: true);

            migrationBuilder.AddColumn<List<string>>(
                name: "agent_capabilities",
                table: "endpoints",
                type: "text[]",
                nullable: false,
                defaultValueSql: "'{}'::text[]");

            migrationBuilder.AddColumn<int>(
                name: "signed_in_users",
                table: "endpoints",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "tray_connected_sessions",
                table: "endpoints",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "windows_update_policy_reported_at",
                table: "endpoints",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "windows_update_policy_status",
                table: "endpoints",
                type: "jsonb",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_policies_endpoint_id",
                table: "policies",
                column: "endpoint_id",
                unique: true,
                filter: "scope = 'Endpoint'");

            migrationBuilder.AddForeignKey(
                name: "FK_policies_endpoints_endpoint_id",
                table: "policies",
                column: "endpoint_id",
                principalTable: "endpoints",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_policies_endpoints_endpoint_id",
                table: "policies");

            migrationBuilder.DropIndex(
                name: "IX_policies_endpoint_id",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "endpoint_id",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "install_notifications_enabled",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "restart_schedule",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "tray_icon_enabled",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "windows_update",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "agent_capabilities",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "signed_in_users",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "tray_connected_sessions",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "windows_update_policy_reported_at",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "windows_update_policy_status",
                table: "endpoints");
        }
    }
}
