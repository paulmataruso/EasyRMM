using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class UserAllOrganizations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "all_organizations",
                table: "users",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            // Until now an empty list meant every organization. Users who have one keep exactly that access. Everyone else
            // stays restricted to their list, and from now on deleting organizations can never widen it.
            migrationBuilder.Sql("""
                UPDATE users SET all_organizations = true
                WHERE NOT EXISTS (SELECT 1 FROM user_organization_access a WHERE a.user_id = users.id);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "all_organizations",
                table: "users");
        }
    }
}
