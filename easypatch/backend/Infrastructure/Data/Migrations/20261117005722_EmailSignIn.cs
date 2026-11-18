using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace EasyPatch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class EmailSignIn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Users sign in with their email address from now on, ignoring case. EasyPatch has always stored addresses trimmed and
            // in lower case, so this normally changes nothing; it stops (and changes nothing) if two users have the same address in
            // different case, because neither could then sign in unambiguously.
            migrationBuilder.Sql(
                """
                DO $$
                DECLARE duplicates text;
                BEGIN
                    SELECT string_agg(address, ', ' ORDER BY address) INTO duplicates
                    FROM (SELECT lower(btrim(email)) AS address FROM users GROUP BY 1 HAVING count(*) > 1) d;
                    IF duplicates IS NOT NULL THEN
                        RAISE EXCEPTION 'EasyPatch users now sign in with their email address, but these addresses belong to more than one user (ignoring case): %. Give each of those users a different email address (Settings -> Users) with the previous EasyPatch version, then upgrade again.', duplicates;
                    END IF;
                END $$;

                UPDATE users SET email = lower(btrim(email)) WHERE email <> lower(btrim(email));

                CREATE UNIQUE INDEX "IX_users_email_lower" ON users (lower(email));
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""DROP INDEX IF EXISTS "IX_users_email_lower";""");
        }
    }
}
