using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_logs",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    username = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: true),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: true),
                    action = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    target_type = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    target_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    details = table.Column<string>(type: "jsonb", nullable: true),
                    ip_address = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    correlation_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_logs", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "organizations",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    description = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    contact_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    contact_email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    notes = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    time_zone = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    archived_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_organizations", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "os_lifecycle_entries",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    product = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    edition_group = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    build_number = table.Column<int>(type: "integer", nullable: false),
                    version_label = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    end_of_servicing = table.Column<DateOnly>(type: "date", nullable: false),
                    esu_end_date = table.Column<DateOnly>(type: "date", nullable: true),
                    notes = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_os_lifecycle_entries", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "server_settings",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false),
                    data = table.Column<string>(type: "jsonb", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_by_user_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_server_settings", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "updates",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    update_guid = table.Column<Guid>(type: "uuid", nullable: false),
                    revision_number = table.Column<int>(type: "integer", nullable: false),
                    title = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    description = table.Column<string>(type: "character varying(8000)", maxLength: 8000, nullable: true),
                    kb_numbers = table.Column<List<string>>(type: "text[]", nullable: false),
                    category = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ms_classification = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    products = table.Column<List<string>>(type: "text[]", nullable: false),
                    msrc_severity = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    release_date = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    max_download_size_bytes = table.Column<long>(type: "bigint", nullable: true),
                    is_driver = table.Column<bool>(type: "boolean", nullable: false),
                    is_optional = table.Column<bool>(type: "boolean", nullable: false),
                    is_mandatory = table.Column<bool>(type: "boolean", nullable: false),
                    reboot_behavior = table.Column<int>(type: "integer", nullable: true),
                    support_url = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    superseded_update_guids = table.Column<List<Guid>>(type: "uuid[]", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_updates", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    username = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    password_hash = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    role = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    mfa_enabled = table.Column<bool>(type: "boolean", nullable: false),
                    mfa_secret_protected = table.Column<string>(type: "text", nullable: true),
                    mfa_pending_secret_protected = table.Column<string>(type: "text", nullable: true),
                    mfa_last_used_step = table.Column<long>(type: "bigint", nullable: true),
                    recovery_code_hashes = table.Column<List<string>>(type: "text[]", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_login_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    failed_login_count = table.Column<int>(type: "integer", nullable: false),
                    lockout_count = table.Column<int>(type: "integer", nullable: false),
                    lockout_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    password_changed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    must_change_password = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "compliance_snapshots",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    date = table.Column<DateOnly>(type: "date", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    total_endpoints = table.Column<int>(type: "integer", nullable: false),
                    compliant = table.Column<int>(type: "integer", nullable: false),
                    missing_updates = table.Column<int>(type: "integer", nullable: false),
                    failed_updates = table.Column<int>(type: "integer", nullable: false),
                    reboot_required = table.Column<int>(type: "integer", nullable: false),
                    scan_stale = table.Column<int>(type: "integer", nullable: false),
                    never_scanned = table.Column<int>(type: "integer", nullable: false),
                    offline = table.Column<int>(type: "integer", nullable: false),
                    missing_required_updates = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_compliance_snapshots", x => x.id);
                    table.ForeignKey(
                        name: "FK_compliance_snapshots_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "sites",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    description = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    address = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    time_zone = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    archived_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_sites", x => x.id);
                    table.ForeignKey(
                        name: "FK_sites_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "password_reset_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_password_reset_tokens", x => x.id);
                    table.ForeignKey(
                        name: "FK_password_reset_tokens_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_organization_access",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_organization_access", x => new { x.user_id, x.organization_id });
                    table.ForeignKey(
                        name: "FK_user_organization_access_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_user_organization_access_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "user_sessions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    mfa_completed = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ip_address = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    user_agent = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_sessions", x => x.id);
                    table.ForeignKey(
                        name: "FK_user_sessions_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "deployment_codes",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    code = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    site_id = table.Column<Guid>(type: "uuid", nullable: true),
                    max_pending_requests = table.Column<int>(type: "integer", nullable: false),
                    allowed_source_cidrs = table.Column<List<string>>(type: "text[]", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
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
                name: "endpoints",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    site_id = table.Column<Guid>(type: "uuid", nullable: true),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    hostname = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    dns_domain = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    domain_joined = table.Column<bool>(type: "boolean", nullable: true),
                    operating_system = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    os_edition = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    os_version = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    os_build = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    os_build_number = table.Column<int>(type: "integer", nullable: true),
                    os_product_type = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    os_install_date = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    architecture = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    serial_number = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    manufacturer = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    model = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    smbios_uuid = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    processor_name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    total_memory_bytes = table.Column<long>(type: "bigint", nullable: true),
                    system_drive_total_bytes = table.Column<long>(type: "bigint", nullable: true),
                    system_drive_free_bytes = table.Column<long>(type: "bigint", nullable: true),
                    is_virtual_machine = table.Column<bool>(type: "boolean", nullable: true),
                    time_zone_id = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    last_boot_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    agent_version = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    agent_installed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    enrolled_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    enrollment_token_id = table.Column<Guid>(type: "uuid", nullable: true),
                    enrollment_request_id = table.Column<Guid>(type: "uuid", nullable: true),
                    last_check_in_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_seen_ip = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    is_online = table.Column<bool>(type: "boolean", nullable: false),
                    current_activity = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    last_inventory_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_scan_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_scan_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_scan_error = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    reboot_pending = table.Column<bool>(type: "boolean", nullable: false),
                    reboot_reasons = table.Column<List<string>>(type: "text[]", nullable: false),
                    reboot_pending_since = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    update_source_type = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    update_source_server = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    microsoft_update_registered = table.Column<bool>(type: "boolean", nullable: false),
                    wufb_policies_configured = table.Column<bool>(type: "boolean", nullable: false),
                    defer_quality_updates_days = table.Column<int>(type: "integer", nullable: true),
                    defer_feature_updates_days = table.Column<int>(type: "integer", nullable: true),
                    target_release_version = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    automatic_updates_mode = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    managed_by_mdm = table.Column<bool>(type: "boolean", nullable: false),
                    windows_update_service_start_mode = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    windows_update_service_state = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    os_support_status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    os_end_of_servicing = table.Column<DateOnly>(type: "date", nullable: true),
                    esu_license_detected = table.Column<bool>(type: "boolean", nullable: false),
                    esu_override = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    compliance_status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    missing_required_count = table.Column<int>(type: "integer", nullable: false),
                    missing_total_count = table.Column<int>(type: "integer", nullable: false),
                    failed_count = table.Column<int>(type: "integer", nullable: false),
                    installed_count = table.Column<int>(type: "integer", nullable: false),
                    pending_reboot_update_count = table.Column<int>(type: "integer", nullable: false),
                    compliance_evaluated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    notes = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_endpoints", x => x.id);
                    table.ForeignKey(
                        name: "FK_endpoints_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_endpoints_sites_site_id",
                        column: x => x.site_id,
                        principalTable: "sites",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "enrollment_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    site_id = table.Column<Guid>(type: "uuid", nullable: true),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    token_prefix = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    description = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    max_uses = table.Column<int>(type: "integer", nullable: false),
                    use_count = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_enrollment_tokens", x => x.id);
                    table.ForeignKey(
                        name: "FK_enrollment_tokens_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_enrollment_tokens_sites_site_id",
                        column: x => x.site_id,
                        principalTable: "sites",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "policies",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    scope = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: true),
                    site_id = table.Column<Guid>(type: "uuid", nullable: true),
                    check_in_interval_seconds = table.Column<int>(type: "integer", nullable: true),
                    scan_interval_minutes = table.Column<int>(type: "integer", nullable: true),
                    inventory_interval_minutes = table.Column<int>(type: "integer", nullable: true),
                    jitter_percent = table.Column<int>(type: "integer", nullable: true),
                    allowed_categories = table.Column<List<string>>(type: "text[]", nullable: true),
                    include_optional = table.Column<bool>(type: "boolean", nullable: true),
                    excluded_kbs = table.Column<List<string>>(type: "text[]", nullable: false),
                    accept_eulas = table.Column<bool>(type: "boolean", nullable: true),
                    auto_install_enabled = table.Column<bool>(type: "boolean", nullable: true),
                    maintenance_days = table.Column<List<int>>(type: "integer[]", nullable: true),
                    maintenance_start = table.Column<TimeOnly>(type: "time without time zone", nullable: true),
                    maintenance_duration_minutes = table.Column<int>(type: "integer", nullable: true),
                    scan_stale_after_hours = table.Column<int>(type: "integer", nullable: true),
                    max_concurrent_installs_per_site = table.Column<int>(type: "integer", nullable: true),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_by_user_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_policies", x => x.id);
                    table.ForeignKey(
                        name: "FK_policies_organizations_organization_id",
                        column: x => x.organization_id,
                        principalTable: "organizations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_policies_sites_site_id",
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
                    request_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    deployment_code_id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    site_id = table.Column<Guid>(type: "uuid", nullable: true),
                    public_key = table.Column<byte[]>(type: "bytea", nullable: false),
                    key_fingerprint = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    hostname = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    device_json = table.Column<string>(type: "jsonb", nullable: false),
                    serial_number = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    os_caption = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    agent_version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    source_ip = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    decided_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    decided_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    reject_reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: true)
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

            migrationBuilder.CreateTable(
                name: "agent_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    credential_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    public_key = table.Column<byte[]>(type: "bytea", nullable: false),
                    algorithm = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    key_fingerprint = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    replaced_by_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_agent_credentials", x => x.id);
                    table.ForeignKey(
                        name: "FK_agent_credentials_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "endpoints",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "endpoint_events",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    type = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    severity = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    message = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: false),
                    details = table.Column<string>(type: "jsonb", nullable: true),
                    job_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_endpoint_events", x => x.id);
                    table.ForeignKey(
                        name: "FK_endpoint_events_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "endpoints",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "endpoint_updates",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    update_guid = table.Column<Guid>(type: "uuid", nullable: false),
                    update_id = table.Column<Guid>(type: "uuid", nullable: false),
                    state = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    is_required = table.Column<bool>(type: "boolean", nullable: false),
                    is_excluded = table.Column<bool>(type: "boolean", nullable: false),
                    first_detected_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_detected_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    state_changed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    installed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_scan_id = table.Column<Guid>(type: "uuid", nullable: true),
                    last_job_id = table.Column<Guid>(type: "uuid", nullable: true),
                    last_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    failed_attempts = table.Column<int>(type: "integer", nullable: false),
                    error_code = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    error_message = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_endpoint_updates", x => x.id);
                    table.ForeignKey(
                        name: "FK_endpoint_updates_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "endpoints",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_endpoint_updates_updates_update_id",
                        column: x => x.update_id,
                        principalTable: "updates",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "jobs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    organization_id = table.Column<Guid>(type: "uuid", nullable: false),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    site_id = table.Column<Guid>(type: "uuid", nullable: true),
                    type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    trigger = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    requested_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    requested_by = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    priority = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    not_before = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    delivered_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    lease_expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    acknowledged_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    completed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_progress_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    delivery_count = table.Column<int>(type: "integer", nullable: false),
                    retry_count = table.Column<int>(type: "integer", nullable: false),
                    retry_of_job_id = table.Column<Guid>(type: "uuid", nullable: true),
                    payload = table.Column<string>(type: "jsonb", nullable: true),
                    result = table.Column<string>(type: "jsonb", nullable: true),
                    progress_percent = table.Column<int>(type: "integer", nullable: true),
                    phase = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    progress_message = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    error_code = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    error_message = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    dedupe_key = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    last_sequence = table.Column<long>(type: "bigint", nullable: false),
                    reboot_required = table.Column<bool>(type: "boolean", nullable: false),
                    timed_out = table.Column<bool>(type: "boolean", nullable: false),
                    cancel_requested_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    cancel_requested_by_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_jobs", x => x.id);
                    table.ForeignKey(
                        name: "FK_jobs_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "endpoints",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "update_exclusions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    update_guid = table.Column<Guid>(type: "uuid", nullable: false),
                    reason = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_update_exclusions", x => x.id);
                    table.ForeignKey(
                        name: "FK_update_exclusions_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "endpoints",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "update_history_entries",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    update_guid = table.Column<Guid>(type: "uuid", nullable: true),
                    revision_number = table.Column<int>(type: "integer", nullable: true),
                    title = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    kb_number = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    operation = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    result_code = table.Column<int>(type: "integer", nullable: false),
                    h_result = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    date = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    client_application_id = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    fingerprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_update_history_entries", x => x.id);
                    table.ForeignKey(
                        name: "FK_update_history_entries_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "endpoints",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "update_scans",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    endpoint_id = table.Column<Guid>(type: "uuid", nullable: false),
                    agent_scan_id = table.Column<Guid>(type: "uuid", nullable: false),
                    job_id = table.Column<Guid>(type: "uuid", nullable: true),
                    trigger = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    completed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    received_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    total_installed = table.Column<int>(type: "integer", nullable: false),
                    total_missing = table.Column<int>(type: "integer", nullable: false),
                    error_code = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    error_message = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    update_source = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_update_scans", x => x.id);
                    table.ForeignKey(
                        name: "FK_update_scans_endpoints_endpoint_id",
                        column: x => x.endpoint_id,
                        principalTable: "endpoints",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "job_updates",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    job_id = table.Column<Guid>(type: "uuid", nullable: false),
                    update_guid = table.Column<Guid>(type: "uuid", nullable: false),
                    revision_number = table.Column<int>(type: "integer", nullable: false),
                    title = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    kb_number = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    category = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    skip_reason = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    result_code = table.Column<int>(type: "integer", nullable: true),
                    error_code = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    error_message = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    reboot_required = table.Column<bool>(type: "boolean", nullable: false),
                    download_percent = table.Column<int>(type: "integer", nullable: true),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    completed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_job_updates", x => x.id);
                    table.ForeignKey(
                        name: "FK_job_updates_jobs_job_id",
                        column: x => x.job_id,
                        principalTable: "jobs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "os_lifecycle_entries",
                columns: new[] { "id", "build_number", "edition_group", "end_of_servicing", "esu_end_date", "notes", "product", "version_label" },
                values: new object[,]
                {
                    { new Guid("010e6621-af8c-1c4f-cf91-5c2c2aad5680"), 14393, "Server", new DateOnly(2027, 1, 12), null, null, "Windows Server", "2016" },
                    { new Guid("20b5581e-b7ce-442f-5655-fe65ba0e8025"), 26100, "Server", new DateOnly(2034, 10, 10), null, null, "Windows Server", "2025" },
                    { new Guid("21efc849-d80b-c398-4a86-b80788718766"), 19044, "HomePro", new DateOnly(2023, 6, 13), null, null, "Windows 10", "21H2" },
                    { new Guid("238e0d93-2ffb-3dba-41ad-45acc2463458"), 26200, "EnterpriseEducation", new DateOnly(2028, 10, 10), null, null, "Windows 11", "25H2" },
                    { new Guid("2c55806c-f608-cf76-d08c-27b6fa0a04bd"), 26100, "IoTLTSC", new DateOnly(2034, 10, 10), null, null, "Windows 11", "IoT LTSC 2024" },
                    { new Guid("38674ee8-f4f9-6011-3d61-c2cde2080258"), 14393, "LTSC", new DateOnly(2026, 10, 13), null, null, "Windows 10", "LTSB 2016" },
                    { new Guid("3f498bee-3a02-0b0d-add4-8c705e391380"), 26100, "EnterpriseEducation", new DateOnly(2027, 10, 12), null, null, "Windows 11", "24H2" },
                    { new Guid("560359d5-b5cf-fc1f-707c-434f06c480d6"), 17763, "LTSC", new DateOnly(2029, 1, 9), null, null, "Windows 10", "LTSC 2019" },
                    { new Guid("5de6fc2d-eb27-9672-18c6-ac40172b1ebb"), 26100, "HomePro", new DateOnly(2026, 10, 13), null, null, "Windows 11", "24H2" },
                    { new Guid("5fd6d521-2fee-9eae-7ed3-d8c7c4728624"), 19044, "IoTLTSC", new DateOnly(2032, 1, 13), null, null, "Windows 10", "IoT LTSC 2021" },
                    { new Guid("6fcbb4ad-5ccb-6f45-f021-dc841408e122"), 10240, "LTSC", new DateOnly(2025, 10, 14), null, null, "Windows 10", "LTSB 2015" },
                    { new Guid("701171d0-89f1-ea80-c30d-eb072818ac3e"), 22631, "HomePro", new DateOnly(2025, 11, 11), null, null, "Windows 11", "23H2" },
                    { new Guid("748d68bd-9aa3-ea11-d91c-366504d4c5a2"), 22000, "HomePro", new DateOnly(2023, 10, 10), null, null, "Windows 11", "21H2" },
                    { new Guid("7cd43378-83a0-180c-c769-50bf5ef03a37"), 19045, "HomePro", new DateOnly(2025, 10, 14), new DateOnly(2028, 10, 10), "ESU: consumer program ended 2026-10-13; commercial ESU through 2028-10-10.", "Windows 10", "22H2" },
                    { new Guid("80335675-62be-61e1-3154-8daa6ec17328"), 17763, "Server", new DateOnly(2029, 1, 9), null, null, "Windows Server", "2019" },
                    { new Guid("855f7212-4fc3-cc72-1eaf-18e52fa842ec"), 20348, "Server", new DateOnly(2031, 10, 14), null, null, "Windows Server", "2022" },
                    { new Guid("865b8351-6821-cb13-9439-47ea4eff4931"), 9200, "Server", new DateOnly(2023, 10, 10), new DateOnly(2026, 10, 13), null, "Windows Server", "2012" },
                    { new Guid("88a91348-d34e-5e41-2aa2-d95d8427eb3c"), 22621, "EnterpriseEducation", new DateOnly(2025, 10, 14), null, null, "Windows 11", "22H2" },
                    { new Guid("8940ae26-b574-7bb7-f5e0-90545ba1bd80"), 17763, "IoTLTSC", new DateOnly(2029, 1, 9), null, null, "Windows 10", "IoT LTSC 2019" },
                    { new Guid("8e6dd03b-39f2-9349-92f4-dacd83e2bbc9"), 19043, "HomePro", new DateOnly(2022, 12, 13), null, null, "Windows 10", "21H1" },
                    { new Guid("9d13d0d4-d2dc-b5b2-c53e-908ea8bccc4a"), 19044, "LTSC", new DateOnly(2027, 1, 12), null, null, "Windows 10", "LTSC 2021" },
                    { new Guid("a0887fd8-6d2c-c181-f092-abf076e968e7"), 22000, "EnterpriseEducation", new DateOnly(2024, 10, 8), null, null, "Windows 11", "21H2" },
                    { new Guid("acb61d69-f330-7823-fdc6-1e668bd6f912"), 9600, "Server", new DateOnly(2023, 10, 10), new DateOnly(2026, 10, 13), null, "Windows Server", "2012 R2" },
                    { new Guid("ad5d0920-9f49-d7a8-2739-c105147f676a"), 22631, "EnterpriseEducation", new DateOnly(2026, 11, 10), null, null, "Windows 11", "23H2" },
                    { new Guid("b5062180-2780-1ded-75e5-630501edc546"), 19043, "EnterpriseEducation", new DateOnly(2022, 12, 13), null, null, "Windows 10", "21H1" },
                    { new Guid("c2dfa57a-519b-e899-ad09-854008a5040b"), 22621, "HomePro", new DateOnly(2024, 10, 8), null, null, "Windows 11", "22H2" },
                    { new Guid("d5c5283d-e24c-4e13-c09f-c69c8cc96752"), 26200, "HomePro", new DateOnly(2027, 10, 12), null, null, "Windows 11", "25H2" },
                    { new Guid("ddeda568-5387-2189-0617-fd37ebb3730e"), 19045, "EnterpriseEducation", new DateOnly(2025, 10, 14), new DateOnly(2028, 10, 10), "Commercial ESU through 2028-10-10.", "Windows 10", "22H2" },
                    { new Guid("dfa43cea-24ce-8359-cee3-3dd6666e1a08"), 26100, "LTSC", new DateOnly(2029, 10, 9), null, null, "Windows 11", "LTSC 2024" },
                    { new Guid("e457bc85-8eab-aeaf-59fd-e600acc6e04d"), 19044, "EnterpriseEducation", new DateOnly(2024, 6, 11), null, null, "Windows 10", "21H2" },
                    { new Guid("e52a218a-e94e-c353-ad3b-8cb33016ac1f"), 14393, "IoTLTSC", new DateOnly(2026, 10, 13), null, null, "Windows 10", "IoT LTSB 2016" }
                });

            migrationBuilder.InsertData(
                table: "server_settings",
                columns: new[] { "id", "data", "updated_at", "updated_by_user_id" },
                values: new object[] { 1, "{}", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), null });

            migrationBuilder.CreateIndex(
                name: "IX_agent_credentials_credential_id",
                table: "agent_credentials",
                column: "credential_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_agent_credentials_endpoint_id",
                table: "agent_credentials",
                column: "endpoint_id");

            migrationBuilder.CreateIndex(
                name: "IX_agent_credentials_key_fingerprint",
                table: "agent_credentials",
                column: "key_fingerprint");

            migrationBuilder.CreateIndex(
                name: "IX_audit_logs_created_at",
                table: "audit_logs",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "IX_audit_logs_organization_id_created_at",
                table: "audit_logs",
                columns: new[] { "organization_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_audit_logs_user_id",
                table: "audit_logs",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "IX_compliance_snapshots_organization_id_date",
                table: "compliance_snapshots",
                columns: new[] { "organization_id", "date" },
                unique: true);

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
                name: "IX_endpoint_events_created_at",
                table: "endpoint_events",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "IX_endpoint_events_endpoint_id_created_at",
                table: "endpoint_events",
                columns: new[] { "endpoint_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_endpoint_events_organization_id_created_at",
                table: "endpoint_events",
                columns: new[] { "organization_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_endpoint_updates_endpoint_id_state",
                table: "endpoint_updates",
                columns: new[] { "endpoint_id", "state" });

            migrationBuilder.CreateIndex(
                name: "IX_endpoint_updates_endpoint_id_update_guid",
                table: "endpoint_updates",
                columns: new[] { "endpoint_id", "update_guid" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_endpoint_updates_update_guid_state",
                table: "endpoint_updates",
                columns: new[] { "update_guid", "state" });

            migrationBuilder.CreateIndex(
                name: "IX_endpoint_updates_update_id",
                table: "endpoint_updates",
                column: "update_id");

            migrationBuilder.CreateIndex(
                name: "IX_endpoints_compliance_status",
                table: "endpoints",
                column: "compliance_status");

            migrationBuilder.CreateIndex(
                name: "IX_endpoints_hostname",
                table: "endpoints",
                column: "hostname");

            migrationBuilder.CreateIndex(
                name: "IX_endpoints_last_check_in_at",
                table: "endpoints",
                column: "last_check_in_at");

            migrationBuilder.CreateIndex(
                name: "IX_endpoints_organization_id",
                table: "endpoints",
                column: "organization_id");

            migrationBuilder.CreateIndex(
                name: "IX_endpoints_organization_id_smbios_uuid",
                table: "endpoints",
                columns: new[] { "organization_id", "smbios_uuid" });

            migrationBuilder.CreateIndex(
                name: "IX_endpoints_site_id",
                table: "endpoints",
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

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_tokens_organization_id",
                table: "enrollment_tokens",
                column: "organization_id");

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_tokens_site_id",
                table: "enrollment_tokens",
                column: "site_id");

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_tokens_token_hash",
                table: "enrollment_tokens",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_job_updates_completed_at",
                table: "job_updates",
                column: "completed_at");

            migrationBuilder.CreateIndex(
                name: "IX_job_updates_job_id_update_guid",
                table: "job_updates",
                columns: new[] { "job_id", "update_guid" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_job_updates_update_guid",
                table: "job_updates",
                column: "update_guid");

            migrationBuilder.CreateIndex(
                name: "IX_jobs_created_at",
                table: "jobs",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "IX_jobs_endpoint_id_status",
                table: "jobs",
                columns: new[] { "endpoint_id", "status" });

            migrationBuilder.CreateIndex(
                name: "IX_jobs_organization_id_created_at",
                table: "jobs",
                columns: new[] { "organization_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_jobs_status_expires_at",
                table: "jobs",
                columns: new[] { "status", "expires_at" });

            migrationBuilder.CreateIndex(
                name: "IX_jobs_status_lease_expires_at",
                table: "jobs",
                columns: new[] { "status", "lease_expires_at" });

            migrationBuilder.CreateIndex(
                name: "ux_jobs_active_dedupe",
                table: "jobs",
                columns: new[] { "endpoint_id", "dedupe_key" },
                unique: true,
                filter: "dedupe_key IS NOT NULL AND status IN ('Queued', 'Delivered', 'Acknowledged', 'Running', 'WaitingForReboot')");

            migrationBuilder.CreateIndex(
                name: "IX_organizations_name",
                table: "organizations",
                column: "name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_os_lifecycle_entries_product_edition_group_build_number",
                table: "os_lifecycle_entries",
                columns: new[] { "product", "edition_group", "build_number" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_password_reset_tokens_token_hash",
                table: "password_reset_tokens",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_password_reset_tokens_user_id",
                table: "password_reset_tokens",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "IX_policies_organization_id",
                table: "policies",
                column: "organization_id",
                unique: true,
                filter: "scope = 'Organization'");

            migrationBuilder.CreateIndex(
                name: "IX_policies_scope",
                table: "policies",
                column: "scope",
                unique: true,
                filter: "scope = 'Global'");

            migrationBuilder.CreateIndex(
                name: "IX_policies_site_id",
                table: "policies",
                column: "site_id",
                unique: true,
                filter: "scope = 'Site'");

            migrationBuilder.CreateIndex(
                name: "IX_sites_organization_id_name",
                table: "sites",
                columns: new[] { "organization_id", "name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_update_exclusions_endpoint_id_update_guid",
                table: "update_exclusions",
                columns: new[] { "endpoint_id", "update_guid" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_update_history_entries_endpoint_id_date",
                table: "update_history_entries",
                columns: new[] { "endpoint_id", "date" });

            migrationBuilder.CreateIndex(
                name: "IX_update_history_entries_endpoint_id_fingerprint",
                table: "update_history_entries",
                columns: new[] { "endpoint_id", "fingerprint" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_update_scans_endpoint_id_agent_scan_id",
                table: "update_scans",
                columns: new[] { "endpoint_id", "agent_scan_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_update_scans_endpoint_id_received_at",
                table: "update_scans",
                columns: new[] { "endpoint_id", "received_at" });

            migrationBuilder.CreateIndex(
                name: "IX_update_scans_received_at",
                table: "update_scans",
                column: "received_at");

            migrationBuilder.CreateIndex(
                name: "IX_updates_category",
                table: "updates",
                column: "category");

            migrationBuilder.CreateIndex(
                name: "IX_updates_update_guid_revision_number",
                table: "updates",
                columns: new[] { "update_guid", "revision_number" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_user_organization_access_organization_id",
                table: "user_organization_access",
                column: "organization_id");

            migrationBuilder.CreateIndex(
                name: "IX_user_sessions_token_hash",
                table: "user_sessions",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_user_sessions_user_id",
                table: "user_sessions",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "IX_users_email",
                table: "users",
                column: "email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_users_username",
                table: "users",
                column: "username",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "agent_credentials");

            migrationBuilder.DropTable(
                name: "audit_logs");

            migrationBuilder.DropTable(
                name: "compliance_snapshots");

            migrationBuilder.DropTable(
                name: "endpoint_events");

            migrationBuilder.DropTable(
                name: "endpoint_updates");

            migrationBuilder.DropTable(
                name: "enrollment_requests");

            migrationBuilder.DropTable(
                name: "enrollment_tokens");

            migrationBuilder.DropTable(
                name: "job_updates");

            migrationBuilder.DropTable(
                name: "os_lifecycle_entries");

            migrationBuilder.DropTable(
                name: "password_reset_tokens");

            migrationBuilder.DropTable(
                name: "policies");

            migrationBuilder.DropTable(
                name: "server_settings");

            migrationBuilder.DropTable(
                name: "update_exclusions");

            migrationBuilder.DropTable(
                name: "update_history_entries");

            migrationBuilder.DropTable(
                name: "update_scans");

            migrationBuilder.DropTable(
                name: "user_organization_access");

            migrationBuilder.DropTable(
                name: "user_sessions");

            migrationBuilder.DropTable(
                name: "updates");

            migrationBuilder.DropTable(
                name: "deployment_codes");

            migrationBuilder.DropTable(
                name: "jobs");

            migrationBuilder.DropTable(
                name: "users");

            migrationBuilder.DropTable(
                name: "endpoints");

            migrationBuilder.DropTable(
                name: "sites");

            migrationBuilder.DropTable(
                name: "organizations");
        }
    }
}
