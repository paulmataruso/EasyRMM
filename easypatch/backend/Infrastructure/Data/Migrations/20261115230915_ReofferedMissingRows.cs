using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class ReofferedMissingRows : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // ReofferedUpdates converted rows that were Failed with the "still missing after a successful installation" message.
            // Before 1.8.0 the next regular scan turned those rows back into Missing and kept the message, so most affected rows
            // (for example KB5007651, installed again by every scheduled installation) were Missing by the time of the upgrade.
            migrationBuilder.Sql(
                """
                UPDATE endpoint_updates
                SET state = 'Reoffered', error_code = 'reoffered', error_message = 'Windows reported the installation as successful, but Windows Update still offers this update. This is a Windows Update detection problem (often seen with Windows Security platform updates such as KB5007651). EasyPatch does not install it again automatically; select it to install it anyway.'
                WHERE state = 'Missing' AND failed_attempts = 0 AND error_code IS NULL
                  AND error_message = 'Installation was reported as successful, but Windows Update still reports the update as missing.';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Nothing to do: ReofferedUpdates' Down turns every Reoffered row back into the pre-1.8.0 Failed state.
        }
    }
}
