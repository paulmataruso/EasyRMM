using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AlertsAndNotifications : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "alert_rules",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    severity = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    threshold = table.Column<int>(type: "integer", nullable: true),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: true),
                    tag_id = table.Column<Guid>(type: "uuid", nullable: true),
                    channel_ids = table.Column<List<Guid>>(type: "uuid[]", nullable: false, defaultValueSql: "'{}'::uuid[]"),
                    notify_on_resolve = table.Column<bool>(type: "boolean", nullable: false),
                    renotify_hours = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_alert_rules", x => x.id);
                    table.ForeignKey(
                        name: "FK_alert_rules_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_alert_rules_tags_tag_id",
                        column: x => x.tag_id,
                        principalTable: "tags",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "notification_channels",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    email_recipients = table.Column<List<string>>(type: "text[]", nullable: false, defaultValueSql: "'{}'::text[]"),
                    webhook_format = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    webhook_url_protected = table.Column<string>(type: "text", nullable: true),
                    webhook_host = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: true),
                    signing_secret_protected = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_notification_channels", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "notification_settings",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false),
                    smtp_host = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: true),
                    smtp_port = table.Column<int>(type: "integer", nullable: false),
                    smtp_security = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    smtp_username = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    smtp_password_protected = table.Column<string>(type: "text", nullable: true),
                    from_address = table.Column<string>(type: "character varying(254)", maxLength: 254, nullable: true),
                    from_name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    allow_private_network_webhooks = table.Column<bool>(type: "boolean", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_notification_settings", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "alerts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    rule_id = table.Column<Guid>(type: "uuid", nullable: true),
                    rule_type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: true),
                    dedupe_key = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    severity = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    title = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    details = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    opened_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    resolved_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    acknowledged_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    acknowledged_by = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    last_notified_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    clear_count = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_alerts", x => x.id);
                    table.ForeignKey(
                        name: "FK_alerts_alert_rules_rule_id",
                        column: x => x.rule_id,
                        principalTable: "alert_rules",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_alerts_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "endpoints",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_alerts_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "notification_deliveries",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    channel_id = table.Column<Guid>(type: "uuid", nullable: false),
                    kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    alert_ids = table.Column<List<Guid>>(type: "uuid[]", nullable: false, defaultValueSql: "'{}'::uuid[]"),
                    subject = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: false),
                    payload = table.Column<string>(type: "jsonb", nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    attempts = table.Column<int>(type: "integer", nullable: false),
                    next_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_error = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    sent_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_notification_deliveries", x => x.id);
                    table.ForeignKey(
                        name: "FK_notification_deliveries_notification_channels_channel_id",
                        column: x => x.channel_id,
                        principalTable: "notification_channels",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            // Default alert rules: enabled, without channels (alerts show in the console until channels are added).
            migrationBuilder.Sql("""
                INSERT INTO alert_rules (id, name, type, enabled, severity, threshold, organization_id, tag_id, channel_ids, notify_on_resolve, renotify_hours, created_at, updated_at)
                VALUES
                ('7c3e1a52-6f0e-4d7b-9a01-000000000001', 'Endpoint offline', 'EndpointOffline', TRUE, 'Warning', 24, NULL, NULL, '{}'::uuid[], FALSE, 0, now(), now()),
                ('7c3e1a52-6f0e-4d7b-9a01-000000000002', 'Update installation failed', 'InstallFailed', TRUE, 'Warning', NULL, NULL, NULL, '{}'::uuid[], FALSE, 0, now(), now()),
                ('7c3e1a52-6f0e-4d7b-9a01-000000000003', 'Security update missing', 'SecurityUpdateMissing', TRUE, 'Critical', 14, NULL, NULL, '{}'::uuid[], FALSE, 0, now(), now()),
                ('7c3e1a52-6f0e-4d7b-9a01-000000000004', 'Scan stale', 'ScanStale', TRUE, 'Warning', NULL, NULL, NULL, '{}'::uuid[], FALSE, 0, now(), now()),
                ('7c3e1a52-6f0e-4d7b-9a01-000000000005', 'Restart pending', 'RestartPending', TRUE, 'Info', 7, NULL, NULL, '{}'::uuid[], FALSE, 0, now(), now()),
                ('7c3e1a52-6f0e-4d7b-9a01-000000000006', 'Enrollment waiting for approval', 'EnrollmentPending', TRUE, 'Info', NULL, NULL, NULL, '{}'::uuid[], FALSE, 0, now(), now()),
                ('7c3e1a52-6f0e-4d7b-9a01-000000000007', 'Operating system unsupported', 'OsUnsupported', TRUE, 'Warning', 30, NULL, NULL, '{}'::uuid[], FALSE, 0, now(), now())
                ON CONFLICT (id) DO NOTHING;
                """);

            migrationBuilder.InsertData(
                table: "notification_settings",
                columns: new[] { "id", "allow_private_network_webhooks", "from_address", "from_name", "smtp_host", "smtp_password_protected", "smtp_port", "smtp_security", "smtp_username", "updated_at" },
                values: new object[] { 1, false, null, null, null, null, 587, "StartTls", null, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)) });

            migrationBuilder.CreateIndex(
                name: "IX_alert_rules_organization_id",
                table: "alert_rules",
                column: "organization_id");

            migrationBuilder.CreateIndex(
                name: "IX_alert_rules_tag_id",
                table: "alert_rules",
                column: "tag_id");

            migrationBuilder.CreateIndex(
                name: "IX_alerts_endpoint_id",
                table: "alerts",
                column: "endpoint_id");

            migrationBuilder.CreateIndex(
                name: "IX_alerts_organization_id",
                table: "alerts",
                column: "organization_id");

            migrationBuilder.CreateIndex(
                name: "IX_alerts_resolved_at",
                table: "alerts",
                column: "resolved_at");

            migrationBuilder.CreateIndex(
                name: "IX_alerts_rule_id",
                table: "alerts",
                column: "rule_id");

            migrationBuilder.CreateIndex(
                name: "IX_alerts_status_organization_id",
                table: "alerts",
                columns: new[] { "status", "organization_id" });

            migrationBuilder.CreateIndex(
                name: "ix_alerts_dedupe_key_unresolved",
                table: "alerts",
                column: "dedupe_key",
                unique: true,
                filter: "status <> 'Resolved'");

            migrationBuilder.CreateIndex(
                name: "IX_notification_deliveries_channel_id_created_at",
                table: "notification_deliveries",
                columns: new[] { "channel_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_notification_deliveries_status_next_attempt_at",
                table: "notification_deliveries",
                columns: new[] { "status", "next_attempt_at" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "alerts");

            migrationBuilder.DropTable(
                name: "notification_deliveries");

            migrationBuilder.DropTable(
                name: "notification_settings");

            migrationBuilder.DropTable(
                name: "alert_rules");

            migrationBuilder.DropTable(
                name: "notification_channels");
        }
    }
}
