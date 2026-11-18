using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class EasyRmmSignIn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "is_easy_rmm",
                table: "oidc_providers",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<Guid>(
                name: "link_user_id",
                table: "oidc_login_states",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_oidc_providers_is_easy_rmm",
                table: "oidc_providers",
                column: "is_easy_rmm",
                unique: true,
                filter: "is_easy_rmm");

            migrationBuilder.CreateIndex(
                name: "IX_oidc_login_states_link_user_id",
                table: "oidc_login_states",
                column: "link_user_id");

            migrationBuilder.AddForeignKey(
                name: "FK_oidc_login_states_users_link_user_id",
                table: "oidc_login_states",
                column: "link_user_id",
                principalTable: "users",
                principalColumn: "id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_oidc_login_states_users_link_user_id",
                table: "oidc_login_states");

            migrationBuilder.DropIndex(
                name: "IX_oidc_providers_is_easy_rmm",
                table: "oidc_providers");

            migrationBuilder.DropIndex(
                name: "IX_oidc_login_states_link_user_id",
                table: "oidc_login_states");

            migrationBuilder.DropColumn(
                name: "is_easy_rmm",
                table: "oidc_providers");

            migrationBuilder.DropColumn(
                name: "link_user_id",
                table: "oidc_login_states");
        }
    }
}
