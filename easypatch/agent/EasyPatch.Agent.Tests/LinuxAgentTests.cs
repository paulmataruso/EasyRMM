using System.Text;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Linux.Packages;
using EasyPatch.Linux.Platform;
using EasyPatch.Linux.Processes;
using EasyPatch.Unix;
using EasyPatch.Unix.Processes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>Package-manager output parsing and version ordering (real output captured from Debian, Ubuntu and Rocky).</summary>
public sealed class LinuxParserTests
{
    [Theory]
    [InlineData("1.0", "1.0", 0)]
    [InlineData("1.0-1", "1.0-2", -1)]
    [InlineData("1:1.0", "2.0", 1)]
    [InlineData("1.0~rc1", "1.0", -1)]
    [InlineData("1.0~rc1", "1.0~", 1)]
    [InlineData("3.0.17-1~deb12u2", "3.0.17-1~deb12u3", -1)]
    [InlineData("2.39-0ubuntu8.9", "2.39-0ubuntu8.12", -1)]
    [InlineData("1.2.3+dfsg-1", "1.2.3-1", 1)]
    [InlineData("1.0a", "1.0", 1)]
    [InlineData("1.0-0ubuntu0.24.04.1", "1.0-0ubuntu0.24.04.10", -1)]
    public void Debian_versions_compare_like_dpkg(string a, string b, int expected)
    {
        Assert.Equal(expected, Math.Sign(DebianVersion.Compare(a, b)));
        Assert.Equal(-expected, Math.Sign(DebianVersion.Compare(b, a)));
    }

    [Theory]
    [InlineData("7.76.1-29.el9_4", "7.76.1-29.el9_4.1", -1)]
    [InlineData("1:3.0.7-27.el9", "3.2.2-6.el9_5", 1)]
    [InlineData("1.0~rc1-1", "1.0-1", -1)]
    [InlineData("1.0^git1-1", "1.0-1", 1)]
    [InlineData("1.0^git1-1", "1.0.1-1", -1)]
    [InlineData("5.14.0-503.14.1.el9_5", "5.14.0-570.el9", -1)]
    [InlineData("2.0a-1", "2.0-1", 1)]
    public void Rpm_versions_compare_like_rpm(string a, string b, int expected)
    {
        Assert.Equal(expected, Math.Sign(RpmVersion.Compare(a, b)));
        Assert.Equal(-expected, Math.Sign(RpmVersion.Compare(b, a)));
    }

    [Fact]
    public void Apt_simulation_lists_upgrades_with_their_origins()
    {
        const string output = """
            NOTE: This is only a simulation!
            Reading package lists...
            Inst libssl3 [3.0.15-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])
            Inst openssl [3.0.15-1~deb12u1] (3.0.17-1~deb12u2 Debian:12.11/stable, Debian-Security:12/stable-security [amd64]) []
            Inst tzdata [2024a-0+deb12u1] (2025b-0+deb12u1 Debian:12.11/stable [all])
            Inst linux-image-6.1.0-37-amd64 (6.1.140-1 Debian:12.11/stable [amd64])
            Inst libc6:i386 [2.36-9+deb12u9] (2.36-9+deb12u10 Debian:12.11/stable [i386])
            Conf libssl3 (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])
            """;

        var upgrades = AptParsers.ParseSimulation(output);

        Assert.Equal(["libssl3", "openssl", "tzdata", "libc6"], upgrades.Select(u => u.Name));
        Assert.True(upgrades[0].Security);
        Assert.True(upgrades[1].Security);
        Assert.False(upgrades[2].Security);
        Assert.Equal("all", upgrades[2].Architecture);
        Assert.Equal("2024a-0+deb12u1", upgrades[2].InstalledVersion);
        Assert.Equal("i386", upgrades[3].Architecture);
        Assert.Equal(["Debian:12.11/stable", "Debian-Security:12/stable-security"], upgrades[1].Origins);
    }

    [Fact]
    public void A_point_release_version_is_security_when_the_security_repository_has_a_newer_version_than_the_installed_one()
    {
        const string madison = """
              libexpat1 | 2.5.0-1+deb12u2 | http://deb.debian.org/debian bookworm/main amd64 Packages
              libexpat1 | 2.5.0-1+deb12u1 | http://deb.debian.org/debian-security bookworm-security/main amd64 Packages
              libexpat1 | 2.5.0-1 | http://deb.debian.org/debian bookworm/main Sources
               tzdata | 2025b-0+deb12u1 | http://deb.debian.org/debian bookworm/main all Packages
            """;
        var entries = AptParsers.ParseMadison(madison);
        var expat = new PackageUpgrade("libexpat1", "amd64", "2.5.0-1", "2.5.0-1+deb12u2", ["Debian:12.11/stable"]);
        var alreadyHasFix = expat with { InstalledVersion = "2.5.0-1+deb12u1" };
        var tzdata = new PackageUpgrade("tzdata", "all", "2024a-0+deb12u1", "2025b-0+deb12u1", ["Debian:12.11/stable"]);

        Assert.Equal(3, entries.Count);
        Assert.True(AptParsers.HasNewerSecurityVersion(expat, entries));
        Assert.False(AptParsers.HasNewerSecurityVersion(alreadyHasFix, entries));
        Assert.False(AptParsers.HasNewerSecurityVersion(tzdata, entries));
    }

    [Fact]
    public void Dpkg_query_output_keeps_fully_installed_packages()
    {
        var installed = AptParsers.ParseInstalled("libssl3\tamd64\t3.0.15-1~deb12u1\tii \nold\tamd64\t1.0\trc \nlibc6\ti386\t2.36-9\tii \n");

        Assert.Equal(2, installed.Count);
        Assert.Equal("3.0.15-1~deb12u1", installed["libssl3:amd64"]);
        Assert.Equal("2.36-9", installed["libc6:i386"]);
    }

    [Fact]
    public void Dnf_check_update_handles_wrapped_rows_notes_and_obsoletes()
    {
        const string output = """

            curl.x86_64                          7.76.1-31.el9_6.1                  baseos
            kernel.x86_64                        5.14.0-570.62.1.el9_6              baseos
            openssl-libs.x86_64                  1:3.2.2-6.el9_5.1                  baseos
            python3-a-very-long-package-name-that-wraps.noarch
                                                 2.1-3.el9                          appstream
            Security: kernel-core-5.14.0-503.14.1.el9_5.x86_64 is an installed security update
            Obsoleting Packages
            grub2-tools.x86_64                   1:2.06-104.el9_6                   baseos
                grub2-tools.x86_64               1:2.06-92.el9                      @baseos
            """;

        var upgrades = DnfParsers.ParseCheckUpdate(output);

        Assert.Equal(["curl", "kernel", "openssl-libs", "python3-a-very-long-package-name-that-wraps"], upgrades.Select(u => u.Name));
        Assert.Equal("1:3.2.2-6.el9_5.1", upgrades[2].Version);
        Assert.Equal("noarch", upgrades[3].Architecture);
        Assert.Equal(["appstream"], upgrades[3].Origins);
    }

    [Fact]
    public void Dnf_updateinfo_lists_advisories_with_severity()
    {
        const string output = """
            RLSA-2025:7425 Important/Sec. curl-7.76.1-31.el9_6.1.x86_64
            RLBA-2025:6922 bugfix         kernel-5.14.0-570.62.1.el9_6.x86_64
            RLSA-2025:9001 Moderate/Sec.  openssl-libs-1:3.2.2-6.el9_5.1.x86_64
            """;

        var advisories = DnfParsers.ParseUpdateInfo(output);

        Assert.Equal(3, advisories.Count);
        Assert.True(advisories[0].IsSecurity);
        Assert.Equal("Important", advisories[0].Severity);
        Assert.Equal("curl", advisories[0].Name);
        Assert.False(advisories[1].IsSecurity);
        Assert.Equal("1:3.2.2-6.el9_5.1", advisories[2].Version);
        Assert.Equal("openssl-libs", advisories[2].Name);
    }

    [Fact]
    public void Dnf_updateinfo_with_cve_lists_only_cve_ids_per_package_version()
    {
        // `dnf updateinfo list --updates --with-cve` on Rocky Linux 9 prints every reference, not only CVEs.
        const string output = """
            CVE-2025-11083  Moderate/Sec.  binutils-2.35.2-67.el9_7.1.x86_64
            RLSA-2025:23343 Moderate/Sec.  binutils-2.35.2-67.el9_7.1.x86_64
            RHSA-2025:23343 Moderate/Sec.  binutils-2.35.2-67.el9_7.1.x86_64
            CC-BY-4.0       Moderate/Sec.  binutils-2.35.2-67.el9_7.1.x86_64
            CVE-2025-11083  Moderate/Sec.  binutils-gold-2.35.2-67.el9_7.1.x86_64
            """;

        var cves = DnfParsers.ParseUpdateInfo(output).Where(a => DnfParsers.IsCve(a.Id)).ToList();

        Assert.Equal(2, cves.Count);
        Assert.All(cves, c => Assert.Equal("CVE-2025-11083", c.Id));
        Assert.Equal(["binutils", "binutils-gold"], cves.Select(c => c.Name));
        Assert.False(DnfParsers.IsCve("CVE-2025-1"));
        Assert.False(DnfParsers.IsCve("cve-2025-11083 "));
    }

    [Fact]
    public void Dnf5_advisory_info_json_maps_advisories_to_cves()
    {
        // Shape of `dnf advisory info --updates --json` (dnf5 5.4): Fedora names CVEs in Bugzilla titles, RHEL-style
        // advisories list them as references of type "cve".
        const string output = """
            [
              {"Name":"FEDORA-2026-3dc7e56d1e","Type":"security","Severity":"Moderate","references":[
                {"Title":"pcre2-10.49 is available","Id":"2526344","Type":"bugzilla","Url":"https://bugzilla.redhat.com/show_bug.cgi?id=2526344"},
                {"Title":"CVE-2026-89162 pcre2: Information disclosure [fedora-all]","Id":"2531754","Type":"bugzilla","Url":"https://bugzilla.redhat.com/x"},
                {"Title":"CVE-2026-89162 pcre2: Information disclosure [fedora-all]","Id":"2531756","Type":"bugzilla","Url":"https://bugzilla.redhat.com/y"},
                {"Title":"cve-2026-89156 pcre2: Out-of-bounds read","Id":"2531803","Type":"bugzilla","Url":"https://bugzilla.redhat.com/z"}
              ],"collections":{"packages":["pcre2-10.49-1.fc45.x86_64"]}},
              {"Name":"RLSA-2026:1234","Type":"security","references":[{"Title":"","Id":"CVE-2026-1111","Type":"cve","Url":""}]},
              {"Name":"FEDORA-2026-eb674199d1","Type":"enhancement","references":[]}
            ]
            """;

        var cves = DnfParsers.ParseAdvisoryCves(output);

        Assert.Equal(["CVE-2026-89156", "CVE-2026-89162"], cves["FEDORA-2026-3dc7e56d1e"]);
        Assert.Equal(["CVE-2026-1111"], cves["RLSA-2026:1234"]);
        Assert.False(cves.ContainsKey("FEDORA-2026-eb674199d1"));
        Assert.Empty(DnfParsers.ParseAdvisoryCves(" "));
        Assert.Throws<System.Text.Json.JsonException>(() => DnfParsers.ParseAdvisoryCves("{}"));
    }

    [Fact]
    public void Dpkg_source_packages_are_keyed_by_name_and_architecture()
    {
        const string output = "libssl3\tamd64\topenssl\nopenssl\tamd64\topenssl\ntzdata\tall\ttzdata\nbad name\tamd64\tx\nlinux-image-6.1.0-40-amd64\tamd64\tlinux-signed-amd64\n";

        var sources = AptParsers.ParseSourcePackages(output);

        Assert.Equal("openssl", sources["libssl3:amd64"]);
        Assert.Equal("tzdata", sources["tzdata:all"]);
        Assert.Equal("linux-signed-amd64", sources["linux-image-6.1.0-40-amd64:amd64"]);
        Assert.Equal(4, sources.Count);
    }

    [Fact]
    public void Dnf5_advisory_json_lists_advisories_with_severity()
    {
        // Shape of `dnf advisory list --updates --json` on Fedora 45 (dnf5 5.4).
        const string output = """
            [
              {"name":"FEDORA-2026-f2ecc7c470","type":"security","severity":"Important","nevra":"curl-8.21.0-9.fc45.x86_64","buildtime":1793840322},
              {"name":"FEDORA-2026-53dfac8ed7","type":"bugfix","severity":"None","nevra":"vim-data-2:9.2.1302-2.fc45.noarch","buildtime":1793840322},
              {"name":"FEDORA-2026-0000000000","type":"security","severity":"None","nevra":"not a nevra"},
              {"name":"FEDORA-2026-1111111111","type":"security"}
            ]
            """;

        var advisories = DnfParsers.ParseAdvisoryJson(output);

        Assert.Equal(2, advisories.Count);
        Assert.True(advisories[0].IsSecurity);
        Assert.Equal("Important", advisories[0].Severity);
        Assert.Equal(("curl", "x86_64", "8.21.0-9.fc45"), (advisories[0].Name, advisories[0].Architecture, advisories[0].Version));
        Assert.False(advisories[1].IsSecurity);
        Assert.Null(advisories[1].Severity);
        Assert.Equal("2:9.2.1302-2.fc45", advisories[1].Version);
        Assert.Empty(DnfParsers.ParseAdvisoryJson(""));
        Assert.Empty(DnfParsers.ParseAdvisoryJson("[]"));
        Assert.Throws<System.Text.Json.JsonException>(() => DnfParsers.ParseAdvisoryJson("{\"advisories\": []}"));
    }

    [Theory]
    [InlineData("  Upgrading        : curl-8.12.1-4.el10_2.8.x86_64_v2                         3/8", "curl")]
    [InlineData("  Installing       : kernel-core-6.12.0-55.el10.x86_64                         1/9", "kernel-core")]
    [InlineData("  Cleanup          : curl-8.12.1-4.el10_2.7.x86_64_v2                         7/8", null)]
    [InlineData("[3/8] Upgrading libnghttp3-0:1.19.0-1.f 100% |   5.0 MiB/s | 164.8 KiB |  00m00s", "libnghttp3")]
    [InlineData("[ 4/12] Upgrading python3-libdnf5-0:5.4. 100% |  52.9 MiB/s |   1.1 MiB |  00m00s", "python3-libdnf5")]
    [InlineData("[5/8] Upgrading a-very-long-package-name-th 100% |   5.1 MiB/s | 490.6 KiB |  00m00s", null)]
    [InlineData("[6/8] Removing curl-0:8.21.0-8.fc45.x86 100% | 620.0   B/s |  18.0   B |  00m00s", null)]
    [InlineData("[1/3] curl-0:8.21.0-9.fc45.x86_64       100% |   0.0   B/s |   0.0   B |  00m00s", null)]
    public void Dnf_transaction_progress_names_the_package_for_dnf4_and_dnf5(string line, string? expected) =>
        Assert.Equal(expected, DnfParsers.ParseProgressPackage(line));

    [Fact]
    public void Rpm_query_keeps_the_newest_install_only_kernel_and_drops_zero_epochs()
    {
        var installed = DnfParsers.ParseInstalled("kernel\tx86_64\t0:5.14.0-427.el9\nkernel\tx86_64\t0:5.14.0-503.14.1.el9_5\nopenssl-libs\tx86_64\t1:3.0.7-27.el9\n");

        Assert.Equal("5.14.0-503.14.1.el9_5", installed["kernel:x86_64"]);
        Assert.Equal("1:3.0.7-27.el9", installed["openssl-libs:x86_64"]);
    }

    [Theory]
    [InlineData("-x")]
    [InlineData("foo;rm")]
    [InlineData("foo bar")]
    [InlineData("$(id)")]
    [InlineData("")]
    public void Names_that_could_be_mistaken_for_options_or_shell_are_rejected(string name)
    {
        Assert.False(PackageNames.IsDebianName(name));
        Assert.False(PackageNames.IsRpmName(name));
    }

    [Fact]
    public void Os_release_is_parsed_with_quotes()
    {
        var distribution = LinuxDistribution.Parse("""
            PRETTY_NAME="Rocky Linux 9.6 (Blue Onyx)"
            NAME="Rocky Linux"
            ID="rocky"
            ID_LIKE="rhel centos fedora"
            VERSION_ID="9.6"
            """)!;

        Assert.Equal("rocky", distribution.Id);
        Assert.Equal(PackageFamily.RedHat, distribution.Family);
        Assert.Equal("9", distribution.ReleaseKey);
        Assert.Equal("Rocky Linux 9", distribution.ProductName);
        Assert.Equal("Rocky Linux 9.6 (Blue Onyx)", distribution.PrettyName);

        var ubuntu = LinuxDistribution.Parse("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n")!;
        Assert.Equal(PackageFamily.Debian, ubuntu.Family);
        Assert.Equal("24.04", ubuntu.ReleaseKey);
        Assert.Equal("Ubuntu 24.04", ubuntu.ProductName);

        Assert.Equal(PackageFamily.Unsupported, LinuxDistribution.Parse("ID=arch\n")!.Family);
        Assert.Null(LinuxDistribution.Parse("NAME=nothing\n"));
    }

    [Fact]
    public void Credentials_in_repository_urls_are_redacted()
    {
        var text = OutputRedactor.Redact("Err:1 https://user:s3cret@repo.example.com/debian bookworm InRelease; https://TOKEN@packagecloud.io/x?token=abc&x=1");

        Assert.DoesNotContain("s3cret", text, StringComparison.Ordinal);
        Assert.DoesNotContain("TOKEN", text, StringComparison.Ordinal);
        Assert.DoesNotContain("abc", text, StringComparison.Ordinal);
        Assert.Contains("https://***@repo.example.com/debian", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("6.1.0-37-amd64", "-amd64")]
    [InlineData("6.1.0-37-cloud-amd64", "-cloud-amd64")]
    [InlineData("6.8.0-60-generic", "-generic")]
    public void Kernel_flavours_are_compared_separately(string release, string flavour) =>
        Assert.Equal(flavour, LinuxRebootDetector.Flavour(release, PackageFamily.Debian));

    [Fact]
    public void A_newer_installed_kernel_of_the_running_flavour_means_a_restart_is_pending()
    {
        using var root = new TempDirectory();
        var modules = Path.Combine(root.Path, "modules");
        var boot = Path.Combine(root.Path, "boot");
        Directory.CreateDirectory(boot);
        foreach (var kernel in new[] { "6.1.0-35-amd64", "6.1.0-37-amd64", "6.1.0-40-cloud-amd64", "6.1.0-41-amd64" })
        {
            Directory.CreateDirectory(Path.Combine(modules, kernel));
        }

        File.WriteAllText(Path.Combine(boot, "vmlinuz-6.1.0-37-amd64"), "");
        File.WriteAllText(Path.Combine(boot, "vmlinuz-6.1.0-40-cloud-amd64"), "");

        // 6.1.0-41 has no kernel image any more (removed; only leftover modules).
        Assert.Equal(("6.1.0-35-amd64", "6.1.0-37-amd64"), LinuxRebootDetector.NewerKernel(PackageFamily.Debian, modules, boot, "6.1.0-35-amd64"));
        Assert.Null(LinuxRebootDetector.NewerKernel(PackageFamily.Debian, modules, boot, "6.1.0-37-amd64"));
    }

    [Fact]
    public void Reboot_behaviour_follows_the_package()
    {
        Assert.Equal(1, PackageUpdateService.RebootBehaviorOf("linux-image-6.1.0-37-amd64"));
        Assert.Equal(1, PackageUpdateService.RebootBehaviorOf("kernel-core"));
        Assert.Equal(0, PackageUpdateService.RebootBehaviorOf("kernel-headers"));
        Assert.Equal(2, PackageUpdateService.RebootBehaviorOf("libc6"));
        Assert.Equal(2, PackageUpdateService.RebootBehaviorOf("glibc"));
        Assert.Equal(0, PackageUpdateService.RebootBehaviorOf("curl"));
    }
}

/// <summary>Scans and installations through a simulated apt (the commands the agent runs are recorded).</summary>
public sealed class LinuxPackageUpdateTests : IDisposable
{
    private static readonly LinuxDistribution Debian = LinuxDistribution.Parse("ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")!;
    private readonly TempDirectory _directory = new();
    private readonly FakeApt _apt = new();
    private readonly ManualTimeProvider _time = new(new DateTimeOffset(2026, 11, 14, 8, 0, 0, TimeSpan.Zero));

    public void Dispose() => _directory.Dispose();

    private PackageUpdateService CreateService()
    {
        var units = new TransientUnitRunner(_apt, NullLogger.Instance) { PollInterval = TimeSpan.Zero };
        var backend = new AptBackend(_apt, units, Path.Combine(_directory.Path, "packages"), NullLogger.Instance);
        return new PackageUpdateService(backend, Debian, Path.Combine(_directory.Path, "ledger.json"), units, null, _time,
            NullLogger<PackageUpdateService>.Instance);
    }

    [Fact]
    public async Task A_scan_reports_one_update_per_package_version_with_stable_ids_and_categories()
    {
        _apt.Installed["libssl3:amd64"] = "3.0.15-1~deb12u1";
        _apt.Installed["tzdata:all"] = "2024a-0+deb12u1";
        _apt.Offer("libssl3", "amd64", "3.0.15-1~deb12u1", "3.0.17-1~deb12u2", "Debian-Security:12/stable-security");
        _apt.Offer("tzdata", "all", "2024a-0+deb12u1", "2025b-0+deb12u1", "Debian:12.11/stable");
        using var service = CreateService();

        using var scan = await service.ScanAsync(includeInstalled: true, CancellationToken.None);

        Assert.Equal(2, scan.Missing.Count);
        var ssl = scan.Missing[0].Update;
        Assert.Equal("libssl3 3.0.17-1~deb12u2", ssl.Title);
        Assert.Equal(PackageUpdateService.UpdateGuidFor(Debian, "libssl3", "amd64", "3.0.17-1~deb12u2"), ssl.UpdateGuid);
        Assert.Equal(["Security Updates", "Debian 12"], ssl.Categories.Select(c => c.Name));
        Assert.True(ssl.Package!.Security);
        Assert.Equal("3.0.15-1~deb12u1", ssl.Package.InstalledVersion);
        Assert.Equal("openssl", ssl.Package.SourcePackage);
        Assert.False(scan.Missing[1].Update.Package!.Security);
        Assert.Equal("tzdata", scan.Missing[1].Update.Package!.SourcePackage);
        Assert.Empty(scan.Installed);
        Assert.Contains(_apt.Commands, c => c.StartsWith("apt-get update", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Installed_updates_are_confirmed_from_the_package_database_and_reported_installed_by_later_scans()
    {
        _apt.Installed["libssl3:amd64"] = "3.0.15-1~deb12u1";
        _apt.Offer("libssl3", "amd64", "3.0.15-1~deb12u1", "3.0.17-1~deb12u2", "Debian-Security:12/stable-security");
        using var service = CreateService();
        using var scan = await service.ScanAsync(includeInstalled: true, CancellationToken.None);

        var results = await service.InstallAsync([scan.Missing[0].Handle], null, CancellationToken.None);

        Assert.True(results[0].IsSuccess);
        Assert.Contains(_apt.Commands, c => c.Contains("systemd-run --unit=easypatch-packages", StringComparison.Ordinal) &&
                                            c.Contains("install -y -q --only-upgrade --no-remove", StringComparison.Ordinal) &&
                                            c.EndsWith("-- libssl3=3.0.17-1~deb12u2", StringComparison.Ordinal));

        using var after = await service.ScanAsync(includeInstalled: true, CancellationToken.None);
        Assert.Empty(after.Missing);
        var installed = Assert.Single(after.Installed);
        Assert.Equal(scan.Missing[0].Update.UpdateGuid, installed.UpdateGuid);
        Assert.True(installed.IsInstalled);
    }

    [Fact]
    public async Task A_failed_transaction_is_retried_one_package_at_a_time_and_only_confirmed_versions_succeed()
    {
        _apt.Installed["curl:amd64"] = "7.88.1-10+deb12u8";
        _apt.Installed["broken:amd64"] = "1.0-1";
        _apt.Offer("curl", "amd64", "7.88.1-10+deb12u8", "7.88.1-10+deb12u12", "Debian-Security:12/stable-security");
        _apt.Offer("broken", "amd64", "1.0-1", "1.0-2", "Debian:12.11/stable");
        _apt.Failing.Add("broken");
        using var service = CreateService();
        using var scan = await service.ScanAsync(includeInstalled: false, CancellationToken.None);

        var results = await service.InstallAsync(scan.Missing.Select(c => c.Handle).ToList(), null, CancellationToken.None);

        Assert.True(results[0].IsSuccess);
        Assert.False(results[1].IsSuccess);
        Assert.Equal("apt_failed", results[1].ErrorCode);
        Assert.Contains("broken 1.0-1 is still installed instead of 1.0-2", results[1].Message, StringComparison.Ordinal);
        Assert.Contains("E: Sub-process /usr/bin/dpkg returned an error code (1)", results[1].Message, StringComparison.Ordinal);
        Assert.Equal(3, _apt.Commands.Count(c => c.Contains("systemd-run", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Automatic_install_marks_are_restored_after_an_installation()
    {
        _apt.Installed["libssl3:amd64"] = "3.0.15-1~deb12u1";
        _apt.Offer("libssl3", "amd64", "3.0.15-1~deb12u1", "3.0.17-1~deb12u2", "Debian-Security:12/stable-security");
        _apt.Auto.Add("libssl3");
        using var service = CreateService();
        using var scan = await service.ScanAsync(includeInstalled: false, CancellationToken.None);

        await service.InstallAsync([scan.Missing[0].Handle], null, CancellationToken.None);

        Assert.Contains("apt-mark auto -- libssl3", _apt.Commands);
        Assert.Contains("libssl3", _apt.Auto);
    }

    [Fact]
    public async Task A_newer_version_supersedes_an_older_one_that_was_never_installed()
    {
        _apt.Installed["curl:amd64"] = "7.88.1-10+deb12u8";
        _apt.Offer("curl", "amd64", "7.88.1-10+deb12u8", "7.88.1-10+deb12u11", "Debian-Security:12/stable-security");
        using var service = CreateService();
        using var first = await service.ScanAsync(includeInstalled: true, CancellationToken.None);

        _apt.Offers.Clear();
        _apt.Offer("curl", "amd64", "7.88.1-10+deb12u8", "7.88.1-10+deb12u12", "Debian-Security:12/stable-security");
        using var second = await service.ScanAsync(includeInstalled: true, CancellationToken.None);

        Assert.Equal([first.Missing[0].Update.UpdateGuid], second.Missing[0].Update.SupersededUpdateGuids);
        Assert.Empty(second.Installed);
    }

    [Fact]
    public async Task A_scan_fails_when_no_package_source_is_configured()
    {
        _apt.NoSources = true;
        using var service = CreateService();

        var ex = await Assert.ThrowsAsync<CommandException>(() => service.ScanAsync(includeInstalled: true, CancellationToken.None));

        Assert.Contains("No apt package sources", ex.Message, StringComparison.Ordinal);
        Assert.Equal("apt_failed", service.DescribeFailure(ex).Code);
    }

    /// <summary>apt, dpkg and systemd as far as the agent sees them.</summary>
    private sealed class FakeApt : ICommandRunner
    {
        private readonly Dictionary<string, (string State, int? Exit)> _units = [];

        public Dictionary<string, string> Installed { get; } = new(StringComparer.Ordinal);

        public List<(string Name, string Arch, string Old, string New, string Origin)> Offers { get; } = [];

        public HashSet<string> Failing { get; } = [];

        public HashSet<string> Auto { get; } = [];

        public List<string> Commands { get; } = [];

        public bool NoSources { get; set; }

        public void Offer(string name, string arch, string old, string version, string origin) => Offers.Add((name, arch, old, version, origin));

        public string? Find(string program) => "/usr/bin/" + program;

        public Task<CommandResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken,
            IReadOnlyDictionary<string, string>? environment = null, byte[]? standardInput = null)
        {
            var line = program + " " + string.Join(' ', arguments);
            Commands.Add(line);
            return Task.FromResult(program switch
            {
                "apt-get" when arguments[0] == "update" => NoSources
                    ? Ok("Reading package lists...\n")
                    : Ok("Hit:1 http://deb.debian.org/debian bookworm InRelease\nReading package lists...\n"),
                "apt-get" when arguments[0] == "-s" => Ok(string.Join('\n', Offers
                    .Where(o => Installed.GetValueOrDefault(o.Name + ":" + o.Arch) == o.Old)
                    .Select(o => $"Inst {o.Name} [{o.Old}] ({o.New} {o.Origin} [{o.Arch}])"))),
                "apt-cache" => Ok(string.Empty),
                "dpkg" when arguments[0] == "--print-architecture" => Ok("amd64\n"),
                "dpkg-query" when arguments[1].Contains("source:Package", StringComparison.Ordinal) => Ok(string.Concat(Installed.Select(i =>
                    $"{i.Key.Split(':')[0]}\t{i.Key.Split(':')[1]}\t{(i.Key.StartsWith("libssl", StringComparison.Ordinal) ? "openssl" : i.Key.Split(':')[0])}\n"))),
                "dpkg-query" => Ok(string.Concat(Installed.Select(i => $"{i.Key.Split(':')[0]}\t{i.Key.Split(':')[1]}\t{i.Value}\tii \n"))),
                "apt-mark" when arguments[0] == "showauto" => Ok(string.Join('\n', Auto)),
                "apt-mark" when arguments[0] == "auto" => MarkAuto(arguments.Skip(2)),
                "systemctl" when arguments[0] == "show" => Show(arguments[1]),
                "systemctl" => Ok(string.Empty),
                "systemd-run" => Start(arguments),
                _ => new CommandResult(127, string.Empty, $"unexpected command {line}"),
            });
        }

        public Task<(int ExitCode, byte[] Output, string Error)> RunBinaryAsync(string program, IReadOnlyList<string> arguments, byte[] standardInput,
            TimeSpan timeout, CancellationToken cancellationToken) => throw new NotSupportedException();

        private CommandResult MarkAuto(IEnumerable<string> names)
        {
            foreach (var name in names)
            {
                Auto.Add(name);
            }

            return Ok(string.Empty);
        }

        private CommandResult Show(string unit) =>
            _units.TryGetValue(unit.Replace(".service", string.Empty, StringComparison.Ordinal), out var u)
                ? Ok($"ActiveState={u.State}\nSubState={(u.State == "active" ? "exited" : "failed")}\nResult={(u.Exit == 0 ? "success" : "exit-code")}\nExecMainStatus={u.Exit}\nLoadState=loaded\n")
                : Ok("ActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=0\nLoadState=not-found\n");

        /// <summary>Runs "apt-get install … -- spec…" at once: every spec not in <see cref="Failing"/> is upgraded.</summary>
        private CommandResult Start(IReadOnlyList<string> arguments)
        {
            var unit = arguments.First(a => a.StartsWith("--unit=", StringComparison.Ordinal))["--unit=".Length..];
            var log = arguments.First(a => a.StartsWith("--property=StandardOutput=file:", StringComparison.Ordinal))["--property=StandardOutput=file:".Length..];
            var separator = arguments.ToList().IndexOf("--");
            var command = arguments.Skip(separator + 1).ToList();
            var specs = command.SkipWhile(a => a != "--").Skip(1).ToList();
            var output = new StringBuilder();
            var failed = specs.Any(s => Failing.Contains(s.Split('=')[0].Split(':')[0]));
            if (!failed)
            {
                foreach (var spec in specs)
                {
                    var name = spec.Split('=')[0].Split(':')[0];
                    var offer = Offers.First(o => o.Name == name);
                    Installed[name + ":" + offer.Arch] = offer.New;
                    Auto.Remove(name); // apt-get install marks packages manual
                    output.Append($"Setting up {name}:{offer.Arch} ({offer.New}) ...\n");
                }
            }
            else
            {
                output.Append("dpkg: error processing package broken (--configure):\nE: Sub-process /usr/bin/dpkg returned an error code (1)\n");
            }

            File.WriteAllText(log, output.ToString());
            _units[unit] = (failed ? "failed" : "active", failed ? 100 : 0);
            return Ok(string.Empty);
        }

        private static CommandResult Ok(string output) => new(0, output, string.Empty);
    }
}

/// <summary>/etc/easypatch/agent.conf handling.</summary>
public sealed class TransientUnitTests
{
    private static readonly CommandResult Running = Show("active", "running", "success", "0");
    private static readonly CommandResult Finished = Show("active", "exited", "success", "0");
    private static readonly CommandResult NoBus = new(1, string.Empty, "Failed to connect to bus: Connection refused");

    [Fact]
    public async Task A_unit_is_not_considered_finished_while_systemd_cannot_report_its_state()
    {
        // systemd re-executes itself when glibc or systemd is upgraded, in the middle of the transaction.
        var systemctl = new FakeSystemctl(Running, NoBus, NoBus, Running, Finished);
        var units = new TransientUnitRunner(systemctl, NullLogger.Instance) { PollInterval = TimeSpan.Zero };

        var exitCode = await units.WaitAsync("easypatch-packages", "/nonexistent/transaction.log", TimeSpan.FromMinutes(5), null, CancellationToken.None);

        Assert.Equal(0, exitCode);
        Assert.Equal(5, systemctl.ShowCalls - 1); // the last show is the reset's
    }

    [Fact]
    public async Task Waiting_gives_up_when_systemd_does_not_report_the_state_for_too_long()
    {
        var systemctl = new FakeSystemctl(Running, NoBus, NoBus, NoBus);
        var units = new TransientUnitRunner(systemctl, NullLogger.Instance) { PollInterval = TimeSpan.Zero, UnavailableLimit = TimeSpan.Zero };

        var ex = await Assert.ThrowsAsync<CommandException>(() =>
            units.WaitAsync("easypatch-packages", "/var/lib/easypatch/packages/transaction.log", TimeSpan.FromMinutes(5), null, CancellationToken.None));

        Assert.Contains("did not report the state of easypatch-packages", ex.Message, StringComparison.Ordinal);
        Assert.Contains("may still be running", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_unit_whose_state_cannot_be_read_counts_as_busy_and_is_not_reset()
    {
        var units = new TransientUnitRunner(new FakeSystemctl(NoBus), NullLogger.Instance);

        Assert.True((await units.GetStatusAsync("easypatch-packages", CancellationToken.None)).IsRunning);
        await Assert.ThrowsAsync<CommandException>(() => units.ResetAsync("easypatch-packages", CancellationToken.None));
    }

    private static CommandResult Show(string active, string sub, string result, string exit) =>
        new(0, $"ActiveState={active}\nSubState={sub}\nResult={result}\nExecMainStatus={exit}\nLoadState=loaded\n", string.Empty);

    /// <summary>Answers <c>systemctl show</c> from a script (the last answer repeats) and accepts stop/reset-failed.</summary>
    private sealed class FakeSystemctl(params CommandResult[] shows) : ICommandRunner
    {
        public int ShowCalls { get; private set; }

        public string? Find(string program) => "/usr/bin/" + program;

        public Task<CommandResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken,
            IReadOnlyDictionary<string, string>? environment = null, byte[]? standardInput = null)
        {
            if (program == "systemctl" && arguments[0] == "show")
            {
                return Task.FromResult(shows[Math.Min(ShowCalls++, shows.Length - 1)]);
            }

            return Task.FromResult(new CommandResult(0, string.Empty, string.Empty));
        }

        public Task<(int ExitCode, byte[] Output, string Error)> RunBinaryAsync(string program, IReadOnlyList<string> arguments, byte[] standardInput,
            TimeSpan timeout, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}

public sealed class LinuxBootstrapTests : IDisposable
{
    private readonly TempDirectory _directory = new();

    public void Dispose() => _directory.Dispose();

    [Fact]
    public void Settings_are_written_root_only_and_the_used_secret_is_removed()
    {
        var path = Path.Combine(_directory.Path, "etc", "agent.conf");
        ConfFileBootstrapSource.Write(path, new BootstrapConfig("https://patch.example.com/", "secret-token", null, null), "Debug");
        var source = new ConfFileBootstrapSource(path);

        var config = source.Read();
        Assert.Equal("https://patch.example.com/", config.ServerUrl);
        Assert.Equal("secret-token", config.EnrollmentToken);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
        Assert.Equal("Debug", source.ReadValue("LogLevel"));

        source.ClearEnrollmentSecrets();

        Assert.DoesNotContain("secret-token", File.ReadAllText(path), StringComparison.Ordinal);
        Assert.Null(source.Read().EnrollmentToken);
        Assert.Equal("https://patch.example.com/", source.Read().ServerUrl);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
    }

    [Fact]
    public void A_world_readable_settings_file_is_restricted_when_read()
    {
        var path = Path.Combine(_directory.Path, "agent.conf");
        File.WriteAllText(path, "# comment\nServerUrl = \"https://patch.example.com\"\nDeploymentCode=ABCD-1234\n");
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead | UnixFileMode.GroupRead);

        var config = new ConfFileBootstrapSource(path).Read();

        Assert.Equal("https://patch.example.com", config.ServerUrl);
        Assert.Equal("ABCD-1234", config.DeploymentCode);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
    }

    [Fact]
    public void The_agent_installer_only_installs_its_own_package_format()
    {
        var units = new TransientUnitRunner(new ProcessCommandRunner(), NullLogger.Instance);
        var deb = new LinuxAgentInstaller(units, PackageFamily.Debian);
        var rpm = new LinuxAgentInstaller(units, PackageFamily.RedHat);

        Assert.Equal("deb", deb.PackageFormat);
        Assert.Equal("apt", deb.DisplayName);
        Assert.Equal("rpm", rpm.PackageFormat);
        Assert.Throws<ArgumentException>(() => deb.Start("/var/lib/easypatch/updates/EasyPatchAgent-1.3.1-x64.rpm", "/var/lib/easypatch/updates/install.log"));
        Assert.Throws<ArgumentException>(() => rpm.Start("/tmp/evil.sh", "/tmp/install.log"));
        Assert.True(deb.IsSuccess(0));
        Assert.False(deb.IsSuccess(100));
    }
}

internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "easypatch-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
    }
}
