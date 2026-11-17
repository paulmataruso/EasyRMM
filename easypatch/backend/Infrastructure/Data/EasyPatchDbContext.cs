using System.Text;
using System.Text.Json;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Json;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EasyPatch.Infrastructure.Data;

public sealed class EasyPatchDbContext(DbContextOptions<EasyPatchDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<UserSession> UserSessions => Set<UserSession>();
    public DbSet<UserOrganizationAccess> UserOrganizationAccess => Set<UserOrganizationAccess>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    public DbSet<ApiToken> ApiTokens => Set<ApiToken>();
    public DbSet<WebAuthnCredential> WebAuthnCredentials => Set<WebAuthnCredential>();
    public DbSet<WebAuthnChallenge> WebAuthnChallenges => Set<WebAuthnChallenge>();
    public DbSet<OidcProvider> OidcProviders => Set<OidcProvider>();
    public DbSet<ExternalLogin> ExternalLogins => Set<ExternalLogin>();
    public DbSet<OidcLoginState> OidcLoginStates => Set<OidcLoginState>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<Site> Sites => Set<Site>();
    public DbSet<Policy> Policies => Set<Policy>();
    public DbSet<Tag> Tags => Set<Tag>();
    public DbSet<EndpointTag> EndpointTags => Set<EndpointTag>();
    public DbSet<OrganizationTag> OrganizationTags => Set<OrganizationTag>();
    public DbSet<SiteTag> SiteTags => Set<SiteTag>();
    public DbSet<ServerSettingsRow> ServerSettings => Set<ServerSettingsRow>();
    public DbSet<OsLifecycleEntry> OsLifecycleEntries => Set<OsLifecycleEntry>();
    public DbSet<ComplianceSnapshot> ComplianceSnapshots => Set<ComplianceSnapshot>();
    public DbSet<Endpoint> Endpoints => Set<Endpoint>();
    public DbSet<AgentCredential> AgentCredentials => Set<AgentCredential>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<DeploymentCode> DeploymentCodes => Set<DeploymentCode>();
    public DbSet<EnrollmentRequest> EnrollmentRequests => Set<EnrollmentRequest>();
    public DbSet<EndpointEvent> EndpointEvents => Set<EndpointEvent>();
    public DbSet<Update> Updates => Set<Update>();
    public DbSet<EndpointUpdate> EndpointUpdates => Set<EndpointUpdate>();
    public DbSet<UpdateExclusion> UpdateExclusions => Set<UpdateExclusion>();
    public DbSet<UpdateHold> UpdateHolds => Set<UpdateHold>();
    public DbSet<UpdateScan> UpdateScans => Set<UpdateScan>();
    public DbSet<UpdateHistoryEntry> UpdateHistoryEntries => Set<UpdateHistoryEntry>();
    public DbSet<Job> Jobs => Set<Job>();
    public DbSet<JobUpdate> JobUpdates => Set<JobUpdate>();
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<MsrcKbCve> MsrcKbCves => Set<MsrcKbCve>();
    public DbSet<MsrcBuildFix> MsrcBuildFixes => Set<MsrcBuildFix>();
    public DbSet<DebianFix> DebianFixes => Set<DebianFix>();
    public DbSet<VulnerabilityFeedState> VulnerabilityFeeds => Set<VulnerabilityFeedState>();
    public DbSet<MirrorState> MirrorStates => Set<MirrorState>();
    public DbSet<ReportSchedule> ReportSchedules => Set<ReportSchedule>();
    public DbSet<GeneratedReport> GeneratedReports => Set<GeneratedReport>();
    public DbSet<NotificationSettingsRow> NotificationSettings => Set<NotificationSettingsRow>();
    public DbSet<NotificationChannel> NotificationChannels => Set<NotificationChannel>();
    public DbSet<AlertRule> AlertRules => Set<AlertRule>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<NotificationDelivery> NotificationDeliveries => Set<NotificationDelivery>();

    /// <summary>SQL list of statuses covered by the duplicate-job guard (used in a partial unique index).</summary>
    internal static readonly string DedupeStatusSql =
        string.Join(", ", JobTransitions.DedupeStatuses.Select(s => $"'{s}'"));

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        // Store enums as readable strings.
        configurationBuilder.Properties<UserRole>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<WebAuthnPurpose>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<EndpointStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<EndpointUpdateState>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<ComplianceStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<OsSupportStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<EsuOverride>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<PolicyScope>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<EnrollmentRequestStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<ScanStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<EventSeverity>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<UpdateCategory>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<JobType>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<JobStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<JobTrigger>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<JobItemStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<ScanTrigger>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<AlertRuleType>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<AlertSeverity>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<AlertStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<NotificationChannelType>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<WebhookFormat>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<SmtpSecurity>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<NotificationKind>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<DeliveryStatus>().HaveConversion<string>().HaveMaxLength(32);
        configurationBuilder.Properties<UpdateHoldSource>().HaveConversion<string>().HaveMaxLength(32);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ConfigureIdentity(modelBuilder);
        ConfigureTenancy(modelBuilder);
        ConfigureEndpoints(modelBuilder);
        ConfigureUpdates(modelBuilder);
        ConfigureJobs(modelBuilder);
        ConfigureNotifications(modelBuilder);
        ConfigureVulnerabilities(modelBuilder);
        ConfigureReports(modelBuilder);
        Seed(modelBuilder);
        ApplySnakeCaseNames(modelBuilder);
    }

    private static void ConfigureIdentity(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.ToTable("users");
            e.Property(x => x.Username).HasMaxLength(64);
            e.Property(x => x.Email).HasMaxLength(256);
            e.Property(x => x.PasswordHash).HasMaxLength(256);
            e.HasIndex(x => x.Username).IsUnique();
            e.HasIndex(x => x.Email).IsUnique();
            e.HasMany(x => x.OrganizationAccess).WithOne().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<UserSession>(e =>
        {
            e.ToTable("user_sessions");
            e.Property(x => x.TokenHash).HasMaxLength(64);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.Property(x => x.UserAgent).HasMaxLength(512);
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasIndex(x => x.UserId);
            e.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<UserOrganizationAccess>(e =>
        {
            e.ToTable("user_organization_access");
            e.HasKey(x => new { x.UserId, x.OrganizationId });
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<WebAuthnCredential>(e =>
        {
            e.ToTable("webauthn_credentials");
            e.Property(x => x.CredentialId).HasMaxLength(1023);
            e.Property(x => x.PublicKey).HasMaxLength(2048);
            e.Property(x => x.Name).HasMaxLength(64);
            e.Property(x => x.AttestationFormat).HasMaxLength(32);
            e.HasIndex(x => x.CredentialId).IsUnique();
            e.HasIndex(x => x.UserId);
            e.HasOne(x => x.User).WithMany(u => u.WebAuthnCredentials).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<WebAuthnChallenge>(e =>
        {
            e.ToTable("webauthn_challenges");
            e.Property(x => x.BindingHash).HasMaxLength(64);
            e.HasIndex(x => x.SessionId);
            e.HasIndex(x => x.BindingHash);
            e.HasIndex(x => x.ExpiresAt);
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<UserSession>().WithMany().HasForeignKey(x => x.SessionId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<OidcProvider>(e =>
        {
            e.ToTable("oidc_providers");
            e.Property(x => x.DisplayName).HasMaxLength(64);
            e.Property(x => x.Issuer).HasMaxLength(512);
            e.Property(x => x.ClientId).HasMaxLength(256);
            e.Property(x => x.Scopes).HasMaxLength(512);
        });
        b.Entity<ExternalLogin>(e =>
        {
            e.ToTable("external_logins");
            e.Property(x => x.Issuer).HasMaxLength(512);
            e.Property(x => x.Subject).HasMaxLength(255);
            e.Property(x => x.Email).HasMaxLength(256);
            e.HasIndex(x => new { x.Issuer, x.Subject }).IsUnique();
            e.HasIndex(x => new { x.ProviderId, x.UserId }).IsUnique(); // one account per provider and user
            e.HasIndex(x => x.UserId);
            e.HasOne(x => x.User).WithMany(u => u.ExternalLogins).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Provider).WithMany().HasForeignKey(x => x.ProviderId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<OidcLoginState>(e =>
        {
            e.ToTable("oidc_login_states");
            e.Property(x => x.StateHash).HasMaxLength(64);
            e.Property(x => x.BindingHash).HasMaxLength(64);
            e.Property(x => x.Nonce).HasMaxLength(64);
            e.Property(x => x.CodeVerifier).HasMaxLength(128);
            e.Property(x => x.ReturnTo).HasMaxLength(2048);
            e.HasIndex(x => x.StateHash).IsUnique();
            e.HasIndex(x => x.ExpiresAt);
            e.HasOne<OidcProvider>().WithMany().HasForeignKey(x => x.ProviderId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<PasswordResetToken>(e =>
        {
            e.ToTable("password_reset_tokens");
            e.Property(x => x.TokenHash).HasMaxLength(64);
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasOne<User>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<ApiToken>(e =>
        {
            e.ToTable("api_tokens");
            e.Property(x => x.Name).HasMaxLength(50);
            e.Property(x => x.Prefix).HasMaxLength(16);
            e.Property(x => x.TokenHash).HasMaxLength(64);
            e.Property(x => x.CreatedBy).HasMaxLength(64);
            e.Property(x => x.RevokedBy).HasMaxLength(64);
            e.Property(x => x.LastUsedIp).HasMaxLength(64);
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasIndex(x => x.Name).IsUnique().HasFilter("revoked_at IS NULL");
        });
        b.Entity<AuditLog>(e =>
        {
            e.ToTable("audit_logs");
            e.Property(x => x.Action).HasMaxLength(128);
            e.Property(x => x.Username).HasMaxLength(64);
            e.Property(x => x.TargetType).HasMaxLength(64);
            e.Property(x => x.TargetId).HasMaxLength(128);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.Property(x => x.CorrelationId).HasMaxLength(64);
            e.Property(x => x.Details).HasColumnType("jsonb");
            e.HasIndex(x => x.CreatedAt);
            e.HasIndex(x => new { x.OrganizationId, x.CreatedAt });
            e.HasIndex(x => x.UserId);
        });
    }

    private static void ConfigureTenancy(ModelBuilder b)
    {
        b.Entity<Organization>(e =>
        {
            e.ToTable("organizations");
            e.Property(x => x.Name).HasMaxLength(200);
            e.Property(x => x.Description).HasMaxLength(2000);
            e.Property(x => x.ContactName).HasMaxLength(200);
            e.Property(x => x.ContactEmail).HasMaxLength(256);
            e.Property(x => x.Notes).HasMaxLength(4000);
            e.Property(x => x.TimeZone).HasMaxLength(64);
            e.HasIndex(x => x.Name).IsUnique();
            e.HasMany(x => x.Sites).WithOne(x => x.Organization).HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<Site>(e =>
        {
            e.ToTable("sites");
            e.Property(x => x.Name).HasMaxLength(200);
            e.Property(x => x.Description).HasMaxLength(2000);
            e.Property(x => x.Address).HasMaxLength(500);
            e.Property(x => x.TimeZone).HasMaxLength(64);
            e.HasIndex(x => new { x.OrganizationId, x.Name }).IsUnique();
        });
        b.Entity<Policy>(e =>
        {
            e.ToTable("policies");
            e.HasIndex(x => x.Scope).IsUnique().HasFilter("scope = 'Global'");
            e.HasIndex(x => x.OrganizationId).IsUnique().HasFilter("scope = 'Organization'");
            e.HasIndex(x => x.SiteId).IsUnique().HasFilter("scope = 'Site'");
            e.HasIndex(x => x.EndpointId).IsUnique().HasFilter("scope = 'Endpoint'");
            e.HasIndex(x => x.TagId).IsUnique().HasFilter("scope = 'Tag'");
            e.HasOne<Tag>().WithMany().HasForeignKey(x => x.TagId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Site>().WithMany().HasForeignKey(x => x.SiteId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Endpoint>().WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
            Json(e.Property(x => x.RestartSchedule));
            Json(e.Property(x => x.WindowsUpdate));
            Json(e.Property(x => x.ApplicationUpdates));
        });
        b.Entity<Tag>(e =>
        {
            e.ToTable("tags");
            e.Property(x => x.Name).HasMaxLength(Tag.MaxNameLength);
            e.Property(x => x.Color).HasMaxLength(16);
            e.Property(x => x.Description).HasMaxLength(500);
            e.HasIndex(x => x.Name).IsUnique();
        });
        b.Entity<EndpointTag>(e =>
        {
            e.ToTable("endpoint_tags");
            e.HasKey(x => new { x.EndpointId, x.TagId });
            e.HasIndex(x => x.TagId);
            e.HasOne<Endpoint>().WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Tag>().WithMany().HasForeignKey(x => x.TagId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<OrganizationTag>(e =>
        {
            e.ToTable("organization_tags");
            e.HasKey(x => new { x.OrganizationId, x.TagId });
            e.HasIndex(x => x.TagId);
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Tag>().WithMany().HasForeignKey(x => x.TagId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<SiteTag>(e =>
        {
            e.ToTable("site_tags");
            e.HasKey(x => new { x.SiteId, x.TagId });
            e.HasIndex(x => x.TagId);
            e.HasOne<Site>().WithMany().HasForeignKey(x => x.SiteId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Tag>().WithMany().HasForeignKey(x => x.TagId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<ServerSettingsRow>(e =>
        {
            e.ToTable("server_settings");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.Data).HasColumnType("jsonb");
        });
        b.Entity<OsLifecycleEntry>(e =>
        {
            e.ToTable("os_lifecycle_entries");
            e.Property(x => x.Product).HasMaxLength(64);
            e.Property(x => x.EditionGroup).HasMaxLength(64);
            e.Property(x => x.VersionLabel).HasMaxLength(64);
            e.Property(x => x.Notes).HasMaxLength(1000);
            e.HasIndex(x => new { x.Product, x.EditionGroup, x.BuildNumber }).IsUnique();
        });
        b.Entity<ComplianceSnapshot>(e =>
        {
            e.ToTable("compliance_snapshots");
            e.HasIndex(x => new { x.OrganizationId, x.Date }).IsUnique();
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });
    }

    private static void ConfigureEndpoints(ModelBuilder b)
    {
        b.Entity<Endpoint>(e =>
        {
            e.ToTable("endpoints");
            e.Property(x => x.Hostname).HasMaxLength(255);
            foreach (var name in new[]
                     {
                         nameof(Endpoint.DnsDomain), nameof(Endpoint.OperatingSystem), nameof(Endpoint.OsEdition),
                         nameof(Endpoint.OsVersion), nameof(Endpoint.OsBuild), nameof(Endpoint.OsProductType),
                         nameof(Endpoint.Architecture), nameof(Endpoint.SerialNumber), nameof(Endpoint.Manufacturer),
                         nameof(Endpoint.Model), nameof(Endpoint.SmbiosUuid), nameof(Endpoint.ProcessorName),
                         nameof(Endpoint.TimeZoneId), nameof(Endpoint.AgentVersion), nameof(Endpoint.LastSeenIp),
                         nameof(Endpoint.CurrentActivity), nameof(Endpoint.UpdateSourceType), nameof(Endpoint.UpdateSourceServer),
                         nameof(Endpoint.TargetReleaseVersion), nameof(Endpoint.AutomaticUpdatesMode),
                         nameof(Endpoint.WindowsUpdateServiceStartMode), nameof(Endpoint.WindowsUpdateServiceState),
                         nameof(Endpoint.KernelVersion),
                     })
            {
                e.Property(name).HasMaxLength(255);
            }

            e.Property(x => x.LastScanError).HasMaxLength(2000);
            e.Property(x => x.Notes).HasMaxLength(4000);
            e.Property(x => x.WindowsUpdatePolicyStatus).HasColumnType("jsonb");
            e.Property(x => x.RebootDetails).HasColumnType("jsonb");
            e.Property(x => x.AgentCapabilities).HasDefaultValueSql("'{}'::text[]");
            e.Property(x => x.AgentReleaseKeyIds).HasDefaultValueSql("'{}'::text[]");
            e.Property(x => x.Platform).HasMaxLength(16).HasDefaultValue(EasyPatch.Contracts.Agent.AgentPlatforms.Windows);
            e.Property(x => x.OsId).HasMaxLength(64);
            e.Property(x => x.PackageManager).HasMaxLength(16);
            e.Property(x => x.WingetVersion).HasMaxLength(32);
            e.Property(x => x.WingetSetupError).HasMaxLength(1000);
            e.Property(x => x.ApplicationScanError).HasMaxLength(1000);
            e.Property(x => x.KeyProtection).HasMaxLength(32);
            e.Property(x => x.AgentPackageFormat).HasMaxLength(8);
            e.HasIndex(x => x.Platform);
            e.HasOne(x => x.Organization).WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne(x => x.Site).WithMany().HasForeignKey(x => x.SiteId).OnDelete(DeleteBehavior.SetNull);
            e.HasIndex(x => x.OrganizationId);
            e.HasIndex(x => x.SiteId);
            e.HasIndex(x => x.Hostname);
            e.HasIndex(x => x.LastCheckInAt);
            e.HasIndex(x => x.ComplianceStatus);
            e.HasIndex(x => new { x.OrganizationId, x.SmbiosUuid });
        });
        b.Entity<AgentCredential>(e =>
        {
            e.ToTable("agent_credentials");
            e.Property(x => x.CredentialId).HasMaxLength(64);
            e.Property(x => x.Algorithm).HasMaxLength(32);
            e.Property(x => x.KeyFingerprint).HasMaxLength(32);
            e.Property(x => x.RevokedReason).HasMaxLength(500);
            e.HasIndex(x => x.CredentialId).IsUnique();
            e.HasIndex(x => x.EndpointId);
            e.HasIndex(x => x.KeyFingerprint);
            e.HasOne(x => x.Endpoint).WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<EnrollmentToken>(e =>
        {
            e.ToTable("enrollment_tokens");
            e.Property(x => x.TokenHash).HasMaxLength(64);
            e.Property(x => x.TokenPrefix).HasMaxLength(16);
            e.Property(x => x.Description).HasMaxLength(500);
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasIndex(x => x.OrganizationId);
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Site>().WithMany().HasForeignKey(x => x.SiteId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<DeploymentCode>(e =>
        {
            e.ToTable("deployment_codes");
            e.Property(x => x.Code).HasMaxLength(64);
            e.Property(x => x.Name).HasMaxLength(200);
            e.HasIndex(x => x.Code).IsUnique();
            e.HasIndex(x => x.OrganizationId);
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Site>().WithMany().HasForeignKey(x => x.SiteId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<EnrollmentRequest>(e =>
        {
            e.ToTable("enrollment_requests");
            e.Property(x => x.RequestId).HasMaxLength(64);
            e.Property(x => x.KeyFingerprint).HasMaxLength(32);
            e.Property(x => x.Hostname).HasMaxLength(255);
            e.Property(x => x.SerialNumber).HasMaxLength(255);
            e.Property(x => x.OsCaption).HasMaxLength(255);
            e.Property(x => x.AgentVersion).HasMaxLength(64);
            e.Property(x => x.SourceIp).HasMaxLength(64);
            e.Property(x => x.RejectReason).HasMaxLength(500);
            e.Property(x => x.DeviceJson).HasColumnType("jsonb");
            e.HasIndex(x => x.RequestId).IsUnique();
            e.HasIndex(x => new { x.DeploymentCodeId, x.Status });
            e.HasIndex(x => x.Status);
            e.HasIndex(x => x.KeyFingerprint);
            e.HasOne<DeploymentCode>().WithMany().HasForeignKey(x => x.DeploymentCodeId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<EndpointEvent>(e =>
        {
            e.ToTable("endpoint_events");
            e.Property(x => x.Type).HasMaxLength(64);
            e.Property(x => x.Message).HasMaxLength(2000);
            e.Property(x => x.Details).HasColumnType("jsonb");
            e.HasIndex(x => new { x.EndpointId, x.CreatedAt });
            e.HasIndex(x => new { x.OrganizationId, x.CreatedAt });
            e.HasIndex(x => x.CreatedAt);
            e.HasOne<Endpoint>().WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
        });
    }

    private static void ConfigureUpdates(ModelBuilder b)
    {
        b.Entity<Update>(e =>
        {
            e.ToTable("updates");
            e.Property(x => x.Title).HasMaxLength(1000);
            e.Property(x => x.Description).HasMaxLength(8000);
            e.Property(x => x.MsClassification).HasMaxLength(128);
            e.Property(x => x.MsrcSeverity).HasMaxLength(32);
            e.Property(x => x.SupportUrl).HasMaxLength(1000);
            e.Property(x => x.PackageName).HasMaxLength(255);
            e.Property(x => x.PackageVersion).HasMaxLength(255);
            e.Property(x => x.PackageArchitecture).HasMaxLength(32);
            e.Property(x => x.PackageRepository).HasMaxLength(255);
            e.Property(x => x.Advisories).HasDefaultValueSql("'{}'::text[]");
            e.Property(x => x.PackageSource).HasMaxLength(255);
            e.Property(x => x.CveIds).HasDefaultValueSql("'{}'::text[]");
            e.HasIndex(x => new { x.UpdateGuid, x.RevisionNumber }).IsUnique();
            e.HasIndex(x => x.KnownExploited).HasFilter("known_exploited");
            e.HasIndex(x => x.Category);
            e.Ignore(x => x.PrimaryKb);
        });
        b.Entity<EndpointUpdate>(e =>
        {
            e.ToTable("endpoint_updates");
            e.Property(x => x.ErrorCode).HasMaxLength(32);
            e.Property(x => x.ErrorMessage).HasMaxLength(2000);
            e.Property(x => x.InstalledVersion).HasMaxLength(255);
            e.HasIndex(x => new { x.EndpointId, x.UpdateGuid }).IsUnique();
            e.HasIndex(x => new { x.EndpointId, x.State });
            e.HasIndex(x => new { x.UpdateGuid, x.State });
            e.HasIndex(x => x.DeferredUntil).HasFilter("deferred_until IS NOT NULL");
            e.Property(x => x.CveIds).HasDefaultValueSql("'{}'::text[]");
            e.HasOne(x => x.Update).WithMany().HasForeignKey(x => x.UpdateId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne<Endpoint>().WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<UpdateExclusion>(e =>
        {
            e.ToTable("update_exclusions");
            e.Property(x => x.Reason).HasMaxLength(500);
            e.HasIndex(x => new { x.EndpointId, x.UpdateGuid }).IsUnique();
            e.HasOne<Endpoint>().WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<UpdateHold>(e =>
        {
            e.ToTable("update_holds");
            e.Property(x => x.Reason).HasMaxLength(500);
            e.Property(x => x.CreatedBy).HasMaxLength(100);
            e.Property(x => x.ReleasedBy).HasMaxLength(100);
            // At most one active hold per update for all organizations, and one per update and organization.
            e.HasIndex(x => x.UpdateGuid).IsUnique().HasFilter("organization_id IS NULL AND released_at IS NULL");
            e.HasIndex(x => new { x.UpdateGuid, x.OrganizationId }).IsUnique().HasFilter("organization_id IS NOT NULL AND released_at IS NULL");
            e.HasIndex(x => x.ReleasedAt);
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<UpdateScan>(e =>
        {
            e.ToTable("update_scans");
            e.Property(x => x.ErrorCode).HasMaxLength(32);
            e.Property(x => x.ErrorMessage).HasMaxLength(2000);
            e.Property(x => x.UpdateSource).HasMaxLength(500);
            e.HasIndex(x => new { x.EndpointId, x.AgentScanId }).IsUnique();
            e.HasIndex(x => new { x.EndpointId, x.ReceivedAt });
            e.HasIndex(x => x.ReceivedAt);
            e.HasOne<Endpoint>().WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<UpdateHistoryEntry>(e =>
        {
            e.ToTable("update_history_entries");
            e.Property(x => x.Title).HasMaxLength(1000);
            e.Property(x => x.KbNumber).HasMaxLength(16);
            e.Property(x => x.Operation).HasMaxLength(32);
            e.Property(x => x.HResult).HasMaxLength(16);
            e.Property(x => x.ClientApplicationId).HasMaxLength(200);
            e.Property(x => x.Fingerprint).HasMaxLength(64);
            e.HasIndex(x => new { x.EndpointId, x.Fingerprint }).IsUnique();
            e.HasIndex(x => new { x.EndpointId, x.Date });
            e.HasOne<Endpoint>().WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
        });
    }

    private static void ConfigureJobs(ModelBuilder b)
    {
        b.Entity<Job>(e =>
        {
            e.ToTable("jobs");
            e.Property(x => x.RequestedBy).HasMaxLength(128);
            e.Property(x => x.Payload).HasColumnType("jsonb");
            e.Property(x => x.Result).HasColumnType("jsonb");
            e.Property(x => x.Phase).HasMaxLength(64);
            e.Property(x => x.ProgressMessage).HasMaxLength(1000);
            e.Property(x => x.ErrorCode).HasMaxLength(64);
            e.Property(x => x.ErrorMessage).HasMaxLength(4000);
            e.Property(x => x.DedupeKey).HasMaxLength(128);
            e.Property(x => x.Version).IsRowVersion();
            e.HasOne(x => x.Endpoint).WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
            e.HasMany(x => x.Updates).WithOne().HasForeignKey(x => x.JobId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.EndpointId, x.Status });
            e.HasIndex(x => new { x.Status, x.ExpiresAt });
            e.HasIndex(x => new { x.Status, x.LeaseExpiresAt });
            e.HasIndex(x => new { x.OrganizationId, x.CreatedAt });
            e.HasIndex(x => x.CreatedAt);
            e.HasIndex(x => new { x.EndpointId, x.DedupeKey })
                .IsUnique()
                .HasDatabaseName("ux_jobs_active_dedupe")
                .HasFilter($"dedupe_key IS NOT NULL AND status IN ({DedupeStatusSql})");
        });
        b.Entity<JobUpdate>(e =>
        {
            e.ToTable("job_updates");
            e.Property(x => x.Title).HasMaxLength(1000);
            e.Property(x => x.KbNumber).HasMaxLength(16);
            e.Property(x => x.SkipReason).HasMaxLength(64);
            e.Property(x => x.ErrorCode).HasMaxLength(32);
            e.Property(x => x.ErrorMessage).HasMaxLength(2000);
            e.HasIndex(x => new { x.JobId, x.UpdateGuid }).IsUnique();
            e.HasIndex(x => x.UpdateGuid);
            e.HasIndex(x => x.CompletedAt);
        });
    }

    /// <summary>Maps a settings record to a jsonb column (serialized with the agent protocol's JSON options).</summary>
    private static void Json<T>(PropertyBuilder<T?> property)
        where T : class
    {
        property.HasColumnType("jsonb").HasConversion(
            v => JsonSerializer.Serialize(v, ContractJson.Options),
            v => JsonSerializer.Deserialize<T>(v, ContractJson.Options),
            new ValueComparer<T?>(
                (a, b) => JsonSerializer.Serialize(a, ContractJson.Options) == JsonSerializer.Serialize(b, ContractJson.Options),
                v => v == null ? 0 : JsonSerializer.Serialize(v, ContractJson.Options).GetHashCode(StringComparison.Ordinal),
                v => v == null ? null : JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(v, ContractJson.Options), ContractJson.Options)));
    }

    private static void ConfigureReports(ModelBuilder b)
    {
        b.Entity<ReportSchedule>(e =>
        {
            e.ToTable("report_schedules");
            e.HasKey(x => x.OrganizationId);
            e.Property(x => x.Recipients).HasDefaultValueSql("'{}'::text[]");
            e.HasOne<Organization>().WithOne().HasForeignKey<ReportSchedule>(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<GeneratedReport>(e =>
        {
            e.ToTable("generated_reports");
            e.HasKey(x => x.Id);
            e.Property(x => x.FileName).HasMaxLength(200);
            e.Property(x => x.Sha256).HasMaxLength(64);
            e.Property(x => x.GeneratedBy).HasMaxLength(255);
            e.Property(x => x.LastError).HasMaxLength(1000);
            e.Property(x => x.Recipients).HasDefaultValueSql("'{}'::text[]");
            e.HasIndex(x => new { x.OrganizationId, x.PeriodStart }).IsUnique().HasFilter("scheduled").HasDatabaseName("ux_generated_reports_scheduled");
            e.HasIndex(x => new { x.OrganizationId, x.GeneratedAt });
            e.HasIndex(x => x.NextAttemptAt).HasFilter("delivery_status = 'Pending'");
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
        });
    }

    private static void ConfigureVulnerabilities(ModelBuilder b)
    {
        b.Entity<Vulnerability>(e =>
        {
            e.ToTable("vulnerabilities");
            e.HasKey(x => x.CveId);
            e.Property(x => x.CveId).HasMaxLength(32);
            e.Property(x => x.Title).HasMaxLength(500);
            e.Property(x => x.Severity).HasMaxLength(16);
            e.Property(x => x.CvssBase).HasPrecision(3, 1);
            e.Property(x => x.KevName).HasMaxLength(500);
            e.HasIndex(x => x.CveId).HasFilter("kev").HasDatabaseName("ix_vulnerabilities_kev");
        });
        b.Entity<MsrcKbCve>(e =>
        {
            e.ToTable("msrc_kb_cves");
            e.HasKey(x => new { x.Kb, x.CveId });
            e.Property(x => x.Kb).HasMaxLength(16);
            e.Property(x => x.CveId).HasMaxLength(32);
        });
        b.Entity<MsrcBuildFix>(e =>
        {
            e.ToTable("msrc_build_fixes");
            e.HasKey(x => new { x.Build, x.CveId });
            e.Property(x => x.CveId).HasMaxLength(32);
            e.HasIndex(x => new { x.Build, x.FixedRevision });
        });
        b.Entity<DebianFix>(e =>
        {
            e.ToTable("debian_fixes");
            e.HasKey(x => new { x.Release, x.Source, x.CveId });
            e.Property(x => x.Release).HasMaxLength(32);
            e.Property(x => x.Source).HasMaxLength(255);
            e.Property(x => x.CveId).HasMaxLength(32);
            e.Property(x => x.FixedVersion).HasMaxLength(200);
        });
        b.Entity<MirrorState>(e =>
        {
            e.ToTable("mirror_states");
            e.HasKey(x => x.Name);
            e.Property(x => x.Name).HasMaxLength(32);
            e.Property(x => x.LastError).HasMaxLength(2000);
        });

        b.Entity<VulnerabilityFeedState>(e =>
        {
            e.ToTable("vulnerability_feeds");
            e.HasKey(x => x.Name);
            e.Property(x => x.Name).HasMaxLength(32);
            e.Property(x => x.LastError).HasMaxLength(1000);
            e.Property(x => x.Version).HasMaxLength(64);
            e.Property(x => x.StateJson).HasColumnType("jsonb");
        });
    }

    private static void ConfigureNotifications(ModelBuilder b)
    {
        b.Entity<NotificationSettingsRow>(e =>
        {
            e.ToTable("notification_settings");
            e.Property(x => x.Id).ValueGeneratedNever();
            e.Property(x => x.SmtpHost).HasMaxLength(253);
            e.Property(x => x.SmtpUsername).HasMaxLength(256);
            e.Property(x => x.FromAddress).HasMaxLength(254);
            e.Property(x => x.FromName).HasMaxLength(100);
        });
        b.Entity<NotificationChannel>(e =>
        {
            e.ToTable("notification_channels");
            e.Property(x => x.Name).HasMaxLength(100);
            e.Property(x => x.WebhookHost).HasMaxLength(253);
            e.Property(x => x.EmailRecipients).HasDefaultValueSql("'{}'::text[]");
        });
        b.Entity<AlertRule>(e =>
        {
            e.ToTable("alert_rules");
            e.Property(x => x.Name).HasMaxLength(100);
            e.Property(x => x.ChannelIds).HasDefaultValueSql("'{}'::uuid[]");
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Tag>().WithMany().HasForeignKey(x => x.TagId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<Alert>(e =>
        {
            e.ToTable("alerts");
            e.Property(x => x.DedupeKey).HasMaxLength(128);
            e.Property(x => x.Title).HasMaxLength(300);
            e.Property(x => x.Details).HasMaxLength(2000);
            e.Property(x => x.AcknowledgedBy).HasMaxLength(64);
            // At most one unresolved alert per subject.
            e.HasIndex(x => x.DedupeKey).IsUnique().HasFilter("status <> 'Resolved'").HasDatabaseName("ix_alerts_dedupe_key_unresolved");
            e.HasIndex(x => new { x.Status, x.OrganizationId });
            e.HasIndex(x => x.EndpointId);
            e.HasIndex(x => x.ResolvedAt);
            e.HasOne<AlertRule>().WithMany().HasForeignKey(x => x.RuleId).OnDelete(DeleteBehavior.SetNull);
            e.HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Endpoint>().WithMany().HasForeignKey(x => x.EndpointId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<NotificationDelivery>(e =>
        {
            e.ToTable("notification_deliveries");
            e.Property(x => x.Subject).HasMaxLength(300);
            e.Property(x => x.Payload).HasColumnType("jsonb");
            e.Property(x => x.LastError).HasMaxLength(500);
            e.Property(x => x.AlertIds).HasDefaultValueSql("'{}'::uuid[]");
            e.HasIndex(x => new { x.Status, x.NextAttemptAt });
            e.HasIndex(x => new { x.ChannelId, x.CreatedAt });
            e.HasOne<NotificationChannel>().WithMany().HasForeignKey(x => x.ChannelId).OnDelete(DeleteBehavior.Cascade);
        });
    }

    private static void Seed(ModelBuilder b)
    {
        var seedTime = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        b.Entity<ServerSettingsRow>().HasData(new ServerSettingsRow { Id = 1, Data = "{}", UpdatedAt = seedTime });
        b.Entity<OsLifecycleEntry>().HasData(LifecycleEvaluator.SeedEntries());
        b.Entity<NotificationSettingsRow>().HasData(new NotificationSettingsRow { Id = 1, UpdatedAt = seedTime });
        // Default alert rules are inserted by the AlertsAndNotifications migration (SQL): HasData cannot seed list columns
        // deterministically.
    }

    private static void ApplySnakeCaseNames(ModelBuilder modelBuilder)
    {
        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
            {
                if (property.Name == nameof(Job.Version) && entity.ClrType == typeof(Job))
                {
                    continue; // mapped to the xmin system column by Npgsql
                }

                property.SetColumnName(ToSnakeCase(property.Name));
            }
        }
    }

    internal static string ToSnakeCase(string name)
    {
        var sb = new StringBuilder(name.Length + 8);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c))
            {
                var prevLower = i > 0 && (char.IsLower(name[i - 1]) || char.IsDigit(name[i - 1]));
                var nextLower = i + 1 < name.Length && char.IsLower(name[i + 1]) && i > 0 && char.IsUpper(name[i - 1]);
                if (i > 0 && (prevLower || nextLower))
                {
                    sb.Append('_');
                }

                sb.Append(char.ToLowerInvariant(c));
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }
}
