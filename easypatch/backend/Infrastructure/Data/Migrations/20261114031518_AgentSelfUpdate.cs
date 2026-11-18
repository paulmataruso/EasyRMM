using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AgentSelfUpdate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "agent_auto_update_enabled",
                table: "policies",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "agent_architecture",
                table: "endpoints",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<List<string>>(
                name: "agent_release_key_ids",
                table: "endpoints",
                type: "text[]",
                nullable: false,
                defaultValueSql: "'{}'::text[]");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "agent_auto_update_enabled",
                table: "policies");

            migrationBuilder.DropColumn(
                name: "agent_architecture",
                table: "endpoints");

            migrationBuilder.DropColumn(
                name: "agent_release_key_ids",
                table: "endpoints");
        }
    }
}
