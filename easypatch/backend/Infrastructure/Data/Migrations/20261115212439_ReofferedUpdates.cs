using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class ReofferedUpdates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Updates that were "still missing after a successful installation" (and not failed by an installation since)
            // are what the Reoffered state describes. They keep their row; compliance is recomputed at the next scan.
            migrationBuilder.Sql(
                """
                UPDATE endpoint_updates
                SET state = 'Reoffered', error_code = 'reoffered', error_message = 'Windows reported the installation as successful, but Windows Update still offers this update. This is a Windows Update detection problem (often seen with Windows Security platform updates such as KB5007651). EasyPatch does not install it again automatically; select it to install it anyway.'
                WHERE state = 'Failed' AND failed_attempts = 0 AND error_code IS NULL
                  AND error_message = 'Installation was reported as successful, but Windows Update still reports the update as missing.';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(
                """
                UPDATE endpoint_updates
                SET state = 'Failed', error_code = NULL,
                    error_message = 'Installation was reported as successful, but Windows Update still reports the update as missing.'
                WHERE state = 'Reoffered';
                """);
        }
    }
}
