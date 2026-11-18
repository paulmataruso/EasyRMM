using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class SecurityKeysAndPasskeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "passkey_prompt_dismissed_at",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "webauthn_challenges",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    session_id = table.Column<Guid>(type: "uuid", nullable: true),
                    binding_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    options_json = table.Column<string>(type: "text", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_webauthn_challenges", x => x.id);
                    table.ForeignKey(
                        name: "FK_webauthn_challenges_user_sessions_session_id",
                        column: x => x.session_id,
                        principalTable: "user_sessions",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_webauthn_challenges_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "webauthn_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    credential_id = table.Column<byte[]>(type: "bytea", maxLength: 1023, nullable: false),
                    public_key = table.Column<byte[]>(type: "bytea", maxLength: 2048, nullable: false),
                    sign_count = table.Column<long>(type: "bigint", nullable: false),
                    aaguid = table.Column<Guid>(type: "uuid", nullable: false),
                    transports = table.Column<List<string>>(type: "text[]", nullable: false),
                    name = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    is_passkey = table.Column<bool>(type: "boolean", nullable: false),
                    is_backup_eligible = table.Column<bool>(type: "boolean", nullable: false),
                    is_backed_up = table.Column<bool>(type: "boolean", nullable: false),
                    attestation_format = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_webauthn_credentials", x => x.id);
                    table.ForeignKey(
                        name: "FK_webauthn_credentials_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_webauthn_challenges_binding_hash",
                table: "webauthn_challenges",
                column: "binding_hash");

            migrationBuilder.CreateIndex(
                name: "IX_webauthn_challenges_expires_at",
                table: "webauthn_challenges",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "IX_webauthn_challenges_session_id",
                table: "webauthn_challenges",
                column: "session_id");

            migrationBuilder.CreateIndex(
                name: "IX_webauthn_challenges_user_id",
                table: "webauthn_challenges",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "IX_webauthn_credentials_credential_id",
                table: "webauthn_credentials",
                column: "credential_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_webauthn_credentials_user_id",
                table: "webauthn_credentials",
                column: "user_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "webauthn_challenges");

            migrationBuilder.DropTable(
                name: "webauthn_credentials");

            migrationBuilder.DropColumn(
                name: "passkey_prompt_dismissed_at",
                table: "users");
        }
    }
}
