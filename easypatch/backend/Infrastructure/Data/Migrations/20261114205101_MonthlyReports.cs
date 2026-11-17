using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class MonthlyReports : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "generated_reports",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    period_start = table.Column<DateOnly>(type: "date", nullable: false),
                    period_end = table.Column<DateOnly>(type: "date", nullable: false),
                    scheduled = table.Column<bool>(type: "boolean", nullable: false),
                    generated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    generated_by = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    file_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    content = table.Column<byte[]>(type: "bytea", nullable: false),
                    size_bytes = table.Column<long>(type: "bigint", nullable: false),
                    sha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    delivery_status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    recipients = table.Column<List<string>>(type: "text[]", nullable: false, defaultValueSql: "'{}'::text[]"),
                    attempts = table.Column<int>(type: "integer", nullable: false),
                    next_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    queued_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    sent_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_error = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_generated_reports", x => x.id);
                    table.ForeignKey(
                        name: "FK_generated_reports_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "report_schedules",
                columns: table => new
                {
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    recipients = table.Column<List<string>>(type: "text[]", nullable: false, defaultValueSql: "'{}'::text[]"),
                    day_of_month = table.Column<int>(type: "integer", nullable: false),
                    include_endpoint_list = table.Column<bool>(type: "boolean", nullable: false),
                    enabled_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_scheduled_period = table.Column<DateOnly>(type: "date", nullable: true),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_report_schedules", x => x.organization_id);
                    table.ForeignKey(
                        name: "FK_report_schedules_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_generated_reports_next_attempt_at",
                table: "generated_reports",
                column: "next_attempt_at",
                filter: "delivery_status = 'Pending'");

            migrationBuilder.CreateIndex(
                name: "IX_generated_reports_organization_id_generated_at",
                table: "generated_reports",
                columns: new[] { "organization_id", "generated_at" });

            migrationBuilder.CreateIndex(
                name: "ux_generated_reports_scheduled",
                table: "generated_reports",
                columns: new[] { "organization_id", "period_start" },
                unique: true,
                filter: "scheduled");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "generated_reports");

            migrationBuilder.DropTable(
                name: "report_schedules");
        }
    }
}
