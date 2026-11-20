using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class DeploymentCodesRetired : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // ADR-0048: deployment codes, the enrollment requests they created and the alert rule that counted the requests
            // went. Alerts and rules of that type would no longer read.
            migrationBuilder.Sql("""DELETE FROM alerts WHERE rule_type = 'EnrollmentPending';""");
            migrationBuilder.Sql("""DELETE FROM alert_rules WHERE type = 'EnrollmentPending';""");

            migrationBuilder.DropTable(
                name: "enrollment_requests");

            migrationBuilder.DropTable(
                name: "deployment_codes");

            migrationBuilder.DropColumn(
                name: "enrollment_request_id",
                table: "endpoints");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "enrollment_request_id",
                table: "endpoints",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "deployment_codes",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    allowed_source_cidrs = table.Column<List<string>>(type: "text[]", nullable: false),
                    code = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    max_pending_requests = table.Column<int>(type: "integer", nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    site_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_deployment_codes", x => x.id);
                    table.ForeignKey(
                        name: "FK_deployment_codes_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_deployment_codes_sites_site_id",
                        column: x => x.site_id,
                        principalTable: "sites",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "enrollment_requests",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    agent_version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    decided_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    decided_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    deployment_code_id = table.Column<Guid>(type: "uuid", nullable: false),
                    device_json = table.Column<string>(type: "jsonb", nullable: false),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    hostname = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    key_fingerprint = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    last_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    os_caption = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    public_key = table.Column<byte[]>(type: "bytea", nullable: false),
                    reject_reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    request_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    serial_number = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    site_id = table.Column<Guid>(type: "uuid", nullable: true),
                    source_ip = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_enrollment_requests", x => x.id);
                    table.ForeignKey(
                        name: "FK_enrollment_requests_deployment_codes_deployment_code_id",
                        column: x => x.deployment_code_id,
                        principalTable: "deployment_codes",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_deployment_codes_code",
                table: "deployment_codes",
                column: "code",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_deployment_codes_organization_id",
                table: "deployment_codes",
                column: "organization_id");

            migrationBuilder.CreateIndex(
                name: "IX_deployment_codes_site_id",
                table: "deployment_codes",
                column: "site_id");

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_requests_deployment_code_id_status",
                table: "enrollment_requests",
                columns: new[] { "deployment_code_id", "status" });

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_requests_key_fingerprint",
                table: "enrollment_requests",
                column: "key_fingerprint");

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_requests_request_id",
                table: "enrollment_requests",
                column: "request_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_requests_status",
                table: "enrollment_requests",
                column: "status");
        }
    }
}
