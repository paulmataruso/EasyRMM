using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using EasyPatch.Agent.Core.Companion;
using EasyPatch.Agent.Core.Logging;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>ADR-0069: the EasyPatch agent restarts the EasyRMM agent's and MeshAgent's services, repairs the EasyRMM agent from its
/// recovery copy after four checks, and collects redacted logs. These run on the Windows and the Linux runner: the rules are tested
/// everywhere, and the checks of a real file on the system they are for.</summary>
public sealed class CompanionRepairTests : IDisposable
{
    private const string Rmm = "easyrmm-agent";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "easypatch-companion-tests", Guid.NewGuid().ToString("N"));

    public CompanionRepairTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Left behind in the temp directory.
        }
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static string Sha(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private sealed class FakeHost : ICompanionHost
    {
        public Dictionary<string, string> States { get; } = new() { ["rmm"] = "stopped", ["mesh"] = "running" };
        public string? RestartError { get; set; }
        public string? Untrusted { get; set; }
        public ProgramResult RunResult { get; set; } = new(0, "Put the agent back in place.", false);
        public string? Journal { get; set; }
        public List<string> Calls { get; } = [];

        public Task<string> ServiceStateAsync(string service, CancellationToken cancellationToken) =>
            Task.FromResult(States.GetValueOrDefault(service, "missing"));

        public Task<string?> RestartServiceAsync(string service, CancellationToken cancellationToken)
        {
            Calls.Add("restart " + service);
            if (RestartError is null)
            {
                States[service] = "running";
            }

            return Task.FromResult(RestartError);
        }

        public Task<string?> ReadJournalAsync(string service, int lines, CancellationToken cancellationToken)
        {
            Calls.Add("journal " + service);
            return Task.FromResult(Journal);
        }

        public Task<string?> CheckTrustAsync(string path, string? stopAt, CancellationToken cancellationToken)
        {
            Calls.Add("trust");
            return Task.FromResult(Untrusted);
        }

        public Task<ProgramResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Calls.Add("run " + program + " " + string.Join(' ', arguments));
            States["rmm"] = RunResult.Succeeded ? "running" : "stopped";
            return Task.FromResult(RunResult);
        }
    }

    private CompanionLayout Layout() => new()
    {
        StateDirectory = Path.Combine(_dir, "state"),
        RecoveryCopy = Path.Combine(_dir, "state", "recovery", "easyrmm-agent"),
        EasyRmmService = "rmm",
        MeshService = "mesh",
        EasyRmmLogFile = Path.Combine(_dir, "state", "logs", "agent.log"),
        MeshLogFile = Path.Combine(_dir, "mesh", "meshagent.log"),
        EasyPatchLogFile = Path.Combine(_dir, "patch", "agent.log"),
    };

    private CompanionRepairService Service(FakeHost host, CompanionLayout? layout = null) =>
        new(layout ?? Layout(), host, NullLogger<CompanionRepairService>.Instance, TimeSpan.FromMilliseconds(1));

    private byte[] WriteCopy(CompanionLayout layout, string content = "the recovery copy")
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        Directory.CreateDirectory(Path.GetDirectoryName(layout.RecoveryCopy)!);
        File.WriteAllBytes(layout.RecoveryCopy, bytes);
        return bytes;
    }

    // ---- the four checks of repairing the EasyRMM agent --------------------------------------------------------------------------

    [Fact]
    public async Task A_repair_runs_the_copys_own_repair_install_after_all_four_checks_and_waits_for_the_service()
    {
        var layout = Layout();
        var sha = Sha(WriteCopy(layout));
        var host = new FakeHost();

        var outcome = await Service(host, layout).RepairEasyRmmAgentAsync(sha, Ct);

        Assert.True(outcome.Succeeded, outcome.Message);
        Assert.Equal(["trust", $"run {layout.RecoveryCopy} repair-install"], host.Calls.Where(c => c is "trust" || c.StartsWith("run", StringComparison.Ordinal)));
        Assert.Contains("==== easyrmm-agent ====", outcome.Diagnostics);
    }

    [Fact]
    public async Task A_repair_is_refused_while_the_update_marker_is_present_and_nothing_else_is_looked_at()
    {
        var layout = Layout();
        var sha = Sha(WriteCopy(layout));
        File.WriteAllText(layout.UpdateMarker, "{}");
        var host = new FakeHost();

        var outcome = await Service(host, layout).RepairEasyRmmAgentAsync(sha, Ct);

        Assert.False(outcome.Succeeded);
        Assert.Equal(CompanionErrors.UpdateInProgress, outcome.ErrorCode);
        Assert.DoesNotContain("trust", host.Calls);
        Assert.DoesNotContain(host.Calls, c => c.StartsWith("run", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_corrupted_copy_is_refused_and_never_run()
    {
        var layout = Layout();
        var sha = Sha(WriteCopy(layout));
        File.WriteAllText(layout.RecoveryCopy, "the recovery copy, changed");
        var host = new FakeHost();

        var outcome = await Service(host, layout).RepairEasyRmmAgentAsync(sha, Ct);

        Assert.False(outcome.Succeeded);
        Assert.Equal(CompanionErrors.HashMismatch, outcome.ErrorCode);
        Assert.DoesNotContain(host.Calls, c => c.StartsWith("run", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_copy_that_cannot_be_trusted_is_refused_before_its_hash_is_looked_at_and_never_run()
    {
        var layout = Layout();
        var sha = Sha(WriteCopy(layout));
        var host = new FakeHost { Untrusted = $"{layout.RecoveryCopy} is owned by user 1000, not by root." };

        var outcome = await Service(host, layout).RepairEasyRmmAgentAsync(sha, Ct);

        // The hash is right: the refusal is the owner's, so the hash was not what stopped it.
        Assert.False(outcome.Succeeded);
        Assert.Equal(CompanionErrors.CopyNotTrusted, outcome.ErrorCode);
        Assert.Contains("owned by user 1000", outcome.Message);
        Assert.DoesNotContain(host.Calls, c => c.StartsWith("run", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_missing_copy_and_a_failing_repair_install_are_reported_with_their_reason()
    {
        var layout = Layout();
        var host = new FakeHost();
        var missing = await Service(host, layout).RepairEasyRmmAgentAsync(new string('a', 64), Ct);
        Assert.Equal(CompanionErrors.CopyMissing, missing.ErrorCode);

        var sha = Sha(WriteCopy(layout));
        host.RunResult = new ProgramResult(1, "this machine is not enrolled", false);
        var failed = await Service(host, layout).RepairEasyRmmAgentAsync(sha, Ct);
        Assert.Equal(CompanionErrors.RepairFailed, failed.ErrorCode);
        Assert.Contains("exited with code 1", failed.Message);
        Assert.Contains("this machine is not enrolled", failed.Diagnostics);
    }

    // ---- restarts and logs -------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task A_restart_restarts_the_service_and_waits_until_it_runs()
    {
        var host = new FakeHost();
        var outcome = await Service(host).RestartAsync(Rmm, Ct);
        Assert.True(outcome.Succeeded, outcome.Message);
        Assert.Contains("restart rmm", host.Calls);

        host.RestartError = "sc start: Access is denied.";
        var failed = await Service(host).RestartAsync(CompanionTargets.MeshAgent, Ct);
        Assert.Equal((false, CompanionErrors.RestartFailed), (failed.Succeeded, failed.ErrorCode));
        Assert.Contains("Access is denied", failed.Message);

        // What the service manager printed may hold a secret: it is redacted in the message too.
        host.RestartError = "systemctl failed: ExecStart=agent --password hunter2hunter2 token=abc12345";
        failed = await Service(host).RestartAsync(CompanionTargets.MeshAgent, Ct);
        Assert.Contains("systemctl failed", failed.Message);
        Assert.DoesNotContain("hunter2hunter2", failed.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("abc12345", failed.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_service_that_does_not_exist_is_said_so()
    {
        var host = new FakeHost();
        host.States.Remove("mesh");
        var outcome = await Service(host).RestartAsync(CompanionTargets.MeshAgent, Ct);
        Assert.Equal(CompanionErrors.ServiceMissing, outcome.ErrorCode);
        Assert.Contains("child of the EasyRMM agent", outcome.Message);
        Assert.DoesNotContain(host.Calls, c => c.StartsWith("restart", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Collecting_logs_returns_the_last_500_lines_of_each_log_redacted_and_within_the_cap()
    {
        var layout = Layout();
        Directory.CreateDirectory(Path.GetDirectoryName(layout.EasyRmmLogFile)!);
        Directory.CreateDirectory(Path.GetDirectoryName(layout.MeshLogFile)!);
        Directory.CreateDirectory(Path.GetDirectoryName(layout.EasyPatchLogFile)!);
        File.WriteAllLines(layout.EasyRmmLogFile, Enumerable.Range(1, 700).Select(i => $"rmm line {i} token=ert_abcdefghijklmnop"));
        File.WriteAllText(layout.MeshLogFile, "mesh started\npassword: hunter2hunter2\n-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG\n-----END PRIVATE KEY-----\n");
        File.WriteAllLines(layout.EasyPatchLogFile, Enumerable.Range(1, 3).Select(i => "patch " + i));
        var host = new FakeHost();

        var outcome = await Service(host, layout).CollectLogsAsync(Ct);

        Assert.True(outcome.Succeeded);
        var text = outcome.Diagnostics!;
        Assert.Contains("rmm line 700", text);
        Assert.Contains("rmm line 201", text);
        Assert.DoesNotContain("rmm line 200 ", text);
        Assert.Contains("patch 3", text);
        Assert.Contains("==== meshagent ====", text);
        foreach (var secret in new[] { "ert_abcdefghijklmnop", "hunter2hunter2", "MIGHAgEAMBMG" })
        {
            Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
        }

        Assert.True(Encoding.UTF8.GetByteCount(text) <= JobDiagnostics.MaxBytes);
        Assert.True(outcome.Message.Length <= JobDiagnostics.MaxMessageLength);
    }

    [Fact]
    public async Task A_log_that_is_not_a_file_is_read_from_the_journal_and_diagnostics_stay_within_256_KiB()
    {
        var layout = Layout();
        Directory.CreateDirectory(Path.GetDirectoryName(layout.MeshLogFile)!);
        // Each log line is long: the three together are far over the cap, so each keeps only the end of what it has.
        File.WriteAllLines(layout.MeshLogFile, Enumerable.Range(1, 500).Select(i => $"mesh {i} " + new string('m', 1500)));
        var host = new FakeHost { Journal = string.Join('\n', Enumerable.Range(1, 500).Select(i => $"journal {i} " + new string('j', 1500))) };

        var outcome = await Service(host, layout).CollectLogsAsync(Ct);

        var text = outcome.Diagnostics!;
        Assert.True(Encoding.UTF8.GetByteCount(text) <= JobDiagnostics.MaxBytes);
        Assert.Contains("journal 500 ", text);
        Assert.Contains("mesh 500 ", text);
        Assert.Contains("[earlier lines dropped]", text);
    }

    [Fact]
    public void Diagnostics_are_cut_at_a_line_and_never_in_the_middle_of_a_character()
    {
        var text = string.Join('\n', Enumerable.Range(1, 2000).Select(i => $"é{i}"));
        var cut = CompanionRepairService.KeepEnd(text, 1000);
        Assert.True(Encoding.UTF8.GetByteCount(cut) <= 1000);
        Assert.StartsWith("[earlier lines dropped]\n", cut, StringComparison.Ordinal);
        Assert.EndsWith("é2000", cut, StringComparison.Ordinal);
        Assert.DoesNotContain('�', cut);
    }

    // ---- redaction: the rules of the EasyRMM agent and the server -----------------------------------------------------------------

    [Theory]
    [InlineData("token=abc12345", "abc12345")]
    [InlineData("Password: hunter2hunter2", "hunter2hunter2")]
    [InlineData("{\"client_secret\":\"s3cr3t-value\"}", "s3cr3t-value")]
    [InlineData("api_key=AKIA1234567890", "AKIA1234567890")]
    [InlineData("privateKey: abcdefgh", "abcdefgh")]
    [InlineData("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi")]
    [InlineData("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz")]
    [InlineData("Cookie: session=abcdef123456", "abcdef123456")]
    [InlineData("enrolling with ert_0123456789abcdef", "0123456789abcdef")]
    [InlineData("enrolled with ept_0123456789abcdef", "0123456789abcdef")]
    [InlineData("sent Bearer abcdef123456 to the server", "abcdef123456")]
    [InlineData("run.exe --password hunter2hunter2 --verbose", "hunter2hunter2")]
    [InlineData("x.ps1 -Password hunter2hunter2 -Name bob", "hunter2hunter2")]
    [InlineData("setup.exe /password hunter2hunter2 /quiet", "hunter2hunter2")]
    [InlineData("tool --token abc12345 go", "abc12345")]
    [InlineData("tool -secret s3cr3tvalue", "s3cr3tvalue")]
    [InlineData("tool --api-key value987654", "value987654")]
    [InlineData("tool -key \"two words\"", "two words")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "MIIEow")]
    [InlineData("-----BEGIN CERTIFICATE-----\nMIIBcut off with no end", "MIIBcut")]
    public void Secrets_are_removed_from_log_text(string text, string secret)
    {
        var redacted = LogRedactor.Redact(text);
        Assert.DoesNotContain(secret, redacted, StringComparison.Ordinal);
        Assert.NotEqual(text, redacted);
    }

    [Theory]
    [InlineData("Job 3f2a installed KB5044284 (restart required).")]
    [InlineData("2026-11-23T10:00:00.123Z INF Agent: checked in with the server")]
    [InlineData("keyboard layout: us")]
    [InlineData("monkey=banana")]
    [InlineData("tool --password --verbose")]
    [InlineData("tool --name hunter2")]
    [InlineData("open /var/secret hunter")]
    public void Ordinary_log_text_is_kept(string text) => Assert.Equal(text, LogRedactor.Redact(text));

    [Theory]
    [InlineData("token", true)]
    [InlineData("apiKey", true)]
    [InlineData("api_key", true)]
    [InlineData("key", true)]
    [InlineData("clientSecret", true)]
    [InlineData("Authorization", true)]
    [InlineData("monkey", false)]
    [InlineData("keyboard", false)]
    [InlineData("hostname", false)]
    public void Names_like_a_secrets_are_recognised(string name, bool secret) => Assert.Equal(secret, LogRedactor.SecretName(name));

    // ---- the rules for the recovery copy's owner and access list, on every system -------------------------------------------------

    [Fact]
    public void Unix_rules_refuse_links_other_owners_and_anything_others_may_write()
    {
        FileTrust.UnixEntry Dir(string p, int uid = 0, int mode = 0b111_101_101) => new(p, uid, mode, 2, "directory");
        FileTrust.UnixEntry File(string p, int uid = 0, int mode = 0b110_100_000, int links = 1, string kind = "regular file") => new(p, uid, mode, links, kind);
        FileTrust.UnixEntry[] Chain(FileTrust.UnixEntry? root = null, FileTrust.UnixEntry? mid = null, FileTrust.UnixEntry? file = null) =>
            [root ?? Dir("/"), mid ?? Dir("/var/lib/easyrmm-agent", mode: 0b111_000_000), file ?? File("/var/lib/easyrmm-agent/recovery/easyrmm-agent")];

        Assert.Null(FileTrust.EvaluateUnix(Chain(), 0));
        Assert.Contains("is a link", FileTrust.EvaluateUnix(Chain(file: File("/x", kind: "symbolic link")), 0));
        Assert.Contains("is a link", FileTrust.EvaluateUnix(Chain(mid: new FileTrust.UnixEntry("/var/lib", 0, 0b111_101_101, 1, "symbolic link")), 0));
        Assert.Contains("hard links", FileTrust.EvaluateUnix(Chain(file: File("/x", links: 2)), 0));
        Assert.Contains("owned by user 1000", FileTrust.EvaluateUnix(Chain(file: File("/x", uid: 1000)), 0));
        Assert.Contains("owned by user 1000", FileTrust.EvaluateUnix(Chain(mid: Dir("/var/lib", uid: 1000)), 0));
        Assert.Contains("group or by others", FileTrust.EvaluateUnix(Chain(file: File("/x", mode: 0b110_110_000)), 0));
        Assert.Contains("group or by others", FileTrust.EvaluateUnix(Chain(file: File("/x", mode: 0b110_000_010)), 0));
        Assert.Contains("group or by others", FileTrust.EvaluateUnix(Chain(root: Dir("/", mode: 0b111_111_111)), 0));
        Assert.Contains("not a program", FileTrust.EvaluateUnix(Chain(file: File("/x", kind: "directory")), 0));
        Assert.Contains("not a directory", FileTrust.EvaluateUnix(Chain(mid: new FileTrust.UnixEntry("/var/lib", 0, 0b111_101_101, 1, "regular file")), 0));
    }

    [Fact]
    public void Stat_output_is_read_back_in_order_and_anything_else_is_not_understood()
    {
        var paths = new[] { "/", "/var" };
        var parsed = FileTrust.ParseStat(paths, "0 755 20 directory\n0 755 15 directory\n");
        Assert.Equal([new FileTrust.UnixEntry("/", 0, 0b111_101_101, 20, "directory"), new FileTrust.UnixEntry("/var", 0, 0b111_101_101, 15, "directory")], parsed);
        Assert.Null(FileTrust.ParseStat(paths, "0 755 20 directory\n"));
        Assert.Null(FileTrust.ParseStat(paths, "0 7x5 20 directory\n0 755 15 directory\n"));
        Assert.Equal("symbolic link", FileTrust.ParseStat(["/l"], "0 777 1 symbolic link\n")![0].Kind);
        Assert.Equal(["/", "/var", "/var/lib"], FileTrust.UnixChain("/var/lib"));
    }

    [Fact]
    public void Windows_rules_let_only_the_system_and_administrators_write_and_ignore_what_cannot_replace_the_folder()
    {
        const string system = "S-1-5-18", admins = "S-1-5-32-544", users = "S-1-5-32-545", everyone = "S-1-1-0", creator = "S-1-3-0";
        const uint full = 0x1F01FF, append = 0x4, read = 0x120089, genericAll = 0x10000000;
        FileTrust.AclEntry Allow(string who, uint mask, byte flags = 0) => new(true, flags, mask, who);

        Assert.Null(FileTrust.Grantee([Allow(system, full), Allow(admins, full), Allow(users, read)], FileTrust.WriteRights, passedOn: false));
        Assert.Equal(users, FileTrust.Grantee([Allow(system, full), Allow(users, 0x2)], FileTrust.WriteRights, passedOn: false));
        Assert.Equal(everyone, FileTrust.Grantee([Allow(everyone, genericAll)], FileTrust.WriteRights, passedOn: false));
        Assert.Equal(users, FileTrust.Grantee([Allow(users, 0x40000)], FileTrust.WriteRights, passedOn: false)); // WRITE_DAC
        Assert.Null(FileTrust.Grantee([Allow(creator, full)], FileTrust.WriteRights, passedOn: false));
        // Denying entries let no one in.
        Assert.Null(FileTrust.Grantee([new FileTrust.AclEntry(false, 0, full, users)], FileTrust.WriteRights, passedOn: false));
        // An entry only passed on to what a folder holds counts on the copy's own folder, not on a folder above it.
        Assert.Equal(users, FileTrust.Grantee([Allow(users, full, flags: 0x08)], FileTrust.WriteRights, passedOn: true));
        Assert.Null(FileTrust.Grantee([Allow(users, full, flags: 0x08)], FileTrust.ReplaceRights, passedOn: false));
        // A drive's root and ProgramData let every user add a folder: that cannot replace the agent's folder.
        Assert.Null(FileTrust.Grantee([Allow(users, append)], FileTrust.ReplaceRights, passedOn: false));
        Assert.Equal(users, FileTrust.Grantee([Allow(users, 0x40)], FileTrust.ReplaceRights, passedOn: false)); // delete what the folder holds
        Assert.True(FileTrust.TrustedWindowsOwner(system) && FileTrust.TrustedWindowsOwner(admins));
        Assert.True(FileTrust.TrustedDirectoryOwner(system) && FileTrust.TrustedDirectoryOwner(admins));
        Assert.True(FileTrust.TrustedDirectoryOwner("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"));
        Assert.False(FileTrust.TrustedDirectoryOwner("S-1-5-21-1-2-3-1001") || FileTrust.TrustedDirectoryOwner(null));
        Assert.False(FileTrust.TrustedWindowsOwner("S-1-5-21-1-2-3-1001"));
    }

    // ---- a real file, on the system it is for ----------------------------------------------------------------------------------------

    private static int CurrentUid()
    {
        using var id = Process.Start(new ProcessStartInfo("/usr/bin/id", "-u") { RedirectStandardOutput = true })!;
        var text = id.StandardOutput.ReadToEnd();
        id.WaitForExit();
        return int.Parse(text.Trim(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private string UnixCopy(out string root)
    {
        root = Path.Combine(_dir, "unix");
        var dir = Path.Combine(root, "recovery");
        Directory.CreateDirectory(dir);
        File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var copy = Path.Combine(dir, "easyrmm-agent");
        File.WriteAllText(copy, "program");
        File.SetUnixFileMode(copy, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return copy;
    }

    [Fact]
    public async Task On_Linux_a_real_copy_passes_and_a_linked_group_writable_or_other_users_copy_is_refused()
    {
        Assert.SkipUnless(OperatingSystem.IsLinux(), "A Linux check.");
        var uid = CurrentUid();
        var copy = UnixCopy(out var root);
        var host = new SystemCompanionHost(new ProcessProgramRunner(), windows: false, trustedUid: uid);

        Assert.Null(await host.CheckTrustAsync(copy, root, Ct));

        // Owned by someone else than the trusted user (root, for a real agent): a user that is not root fails the real rule.
        if (uid != 0)
        {
            var strict = new SystemCompanionHost(new ProcessProgramRunner(), windows: false);
            Assert.Contains("not by root", await strict.CheckTrustAsync(copy, root, Ct));
        }

        // Group-writable.
        File.SetUnixFileMode(copy, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupWrite);
        Assert.Contains("group or by others", await host.CheckTrustAsync(copy, root, Ct));
        File.SetUnixFileMode(copy, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Assert.Null(await host.CheckTrustAsync(copy, root, Ct));

        // A directory above that others may write.
        File.SetUnixFileMode(Path.GetDirectoryName(copy)!, (UnixFileMode)0b111_000_111);
        Assert.Contains("group or by others", await host.CheckTrustAsync(copy, root, Ct));
        File.SetUnixFileMode(Path.GetDirectoryName(copy)!, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        // A link to the copy, and a copy in a directory that is a link.
        var link = Path.Combine(root, "link");
        File.CreateSymbolicLink(link, copy);
        Assert.Contains("is a link", await host.CheckTrustAsync(link, root, Ct));
        var linkedDir = Path.Combine(root, "linked");
        Directory.CreateSymbolicLink(linkedDir, Path.GetDirectoryName(copy)!);
        Assert.Contains("is a link", await host.CheckTrustAsync(Path.Combine(linkedDir, "easyrmm-agent"), root, Ct));

        // A second name for the same file.
        var other = Path.Combine(root, "other-name");
        var ln = Process.Start(new ProcessStartInfo("/usr/bin/ln", [copy, other]))!;
        await ln.WaitForExitAsync(Ct);
        Assert.Contains("hard links", await host.CheckTrustAsync(copy, root, Ct));
    }

    [Fact]
    public async Task On_Windows_a_real_copy_passes_and_a_linked_or_users_writable_copy_is_refused()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "A Windows check.");
        var root = Path.Combine(_dir, "win");
        var folder = Path.Combine(root, "recovery");
        Directory.CreateDirectory(folder);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        foreach (var d in new[] { root, folder })
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (var sid in new[] { system, admins })
            {
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
            }

            security.SetOwner(admins);
            new DirectoryInfo(d).SetAccessControl(security);
        }

        var copy = Path.Combine(folder, "easyrmm-agent.exe");
        File.WriteAllText(copy, "program");
        var host = new SystemCompanionHost(new ProcessProgramRunner(), windows: true);

        Assert.Null(await host.CheckTrustAsync(copy, root, Ct));

        // Users may write the copy.
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        var file = new FileInfo(copy);
        var acl = file.GetAccessControl();
        acl.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.Write, AccessControlType.Allow));
        file.SetAccessControl(acl);
        Assert.Contains("may be changed by " + users.Value, await host.CheckTrustAsync(copy, root, Ct));
        acl.RemoveAccessRule(new FileSystemAccessRule(users, FileSystemRights.Write, AccessControlType.Allow));
        file.SetAccessControl(acl);
        Assert.Null(await host.CheckTrustAsync(copy, root, Ct));

        // Users may delete what the folder holds: the copy could be replaced.
        var dir = new DirectoryInfo(folder);
        var dirAcl = dir.GetAccessControl();
        dirAcl.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.DeleteSubdirectoriesAndFiles, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(dirAcl);
        Assert.Contains("may be changed by " + users.Value, await host.CheckTrustAsync(copy, root, Ct));
        dirAcl.RemoveAccessRule(new FileSystemAccessRule(users, FileSystemRights.DeleteSubdirectoriesAndFiles, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        dir.SetAccessControl(dirAcl);

        // An owner who is not the system or the administration can rewrite the folder's access list.
        var me = WindowsIdentity.GetCurrent().User!;
        var ownedDir = dir.GetAccessControl();
        ownedDir.SetOwner(me);
        dir.SetAccessControl(ownedDir);
        Assert.Contains($"{folder} is owned by {me.Value}", await host.CheckTrustAsync(copy, root, Ct));
        ownedDir.SetOwner(admins);
        dir.SetAccessControl(ownedDir);
        Assert.Null(await host.CheckTrustAsync(copy, root, Ct));

        // A link to the copy.
        var link = Path.Combine(root, "link.exe");
        File.CreateSymbolicLink(link, copy);
        Assert.Contains("link or reparse point", await host.CheckTrustAsync(link, root, Ct));

        // A copy in a folder that is a junction or a link.
        var linkedDir = Path.Combine(root, "linked");
        Directory.CreateSymbolicLink(linkedDir, folder);
        Assert.Contains("link or reparse point", await host.CheckTrustAsync(Path.Combine(linkedDir, "easyrmm-agent.exe"), root, Ct));
    }

    // ---- the job, through the real runtime -------------------------------------------------------------------------------------------

    private AgentHarness Harness(FakeHost host, CompanionLayout layout) =>
        new(configurePlatform: p => p with { CompanionRepair = Service(host, layout) });

    private static AgentJob Job(string target, string step, string? sha = null) => AgentHarness.SimpleJob(JobType.RepairCompanion) with
    {
        RepairCompanion = new RepairCompanionPayload { Target = target, Step = step, ExpectedSha256 = sha },
    };

    [Fact]
    public async Task The_capabilities_are_declared_only_with_the_companion_service()
    {
        using var without = new AgentHarness();
        await without.EnrollWithTokenAsync();
        await without.Runtime.CheckInOnceAsync(Ct);
        Assert.DoesNotContain(AgentCapabilities.RepairCompanion, without.Server.CheckIns[^1].Capabilities);
        Assert.DoesNotContain(AgentCapabilities.CollectLogs, without.Server.CheckIns[^1].Capabilities);

        using var with = Harness(new FakeHost(), Layout());
        await with.EnrollWithTokenAsync();
        await with.Runtime.CheckInOnceAsync(Ct);
        Assert.Contains(AgentCapabilities.RepairCompanion, with.Server.CheckIns[^1].Capabilities);
        Assert.Contains(AgentCapabilities.CollectLogs, with.Server.CheckIns[^1].Capabilities);
    }

    [Fact]
    public async Task A_repair_job_reports_its_outcome_and_diagnostics_apart_from_the_message()
    {
        var layout = Layout();
        var sha = Sha(WriteCopy(layout));
        Directory.CreateDirectory(Path.GetDirectoryName(layout.EasyRmmLogFile)!);
        File.WriteAllText(layout.EasyRmmLogFile, "agent started\nenrolled with ert_0123456789abcdef\n");
        var host = new FakeHost();
        using var h = Harness(host, layout);
        await h.EnrollWithTokenAsync();
        var job = Job(Rmm, "repair", sha);
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var reports = h.Server.StatusesFor(job.JobId);
        Assert.Equal(["Repairing", "Completed"], reports.Select(r => r.Phase));
        var final = reports[^1];
        Assert.Equal(JobStatus.Completed, final.Status);
        Assert.Contains("Repaired the EasyRMM agent", final.Message);
        Assert.DoesNotContain("agent started", final.Message);
        Assert.Contains("agent started", final.Diagnostics);
        Assert.DoesNotContain("0123456789abcdef", final.Diagnostics, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_refused_repair_fails_the_job_with_the_reason_and_runs_nothing()
    {
        var layout = Layout();
        WriteCopy(layout);
        var host = new FakeHost();
        using var h = Harness(host, layout);
        await h.EnrollWithTokenAsync();
        var job = Job(Rmm, "repair", new string('0', 64));
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal((JobStatus.Failed, CompanionErrors.HashMismatch), (final.Status, final.ErrorCode));
        Assert.DoesNotContain(host.Calls, c => c.StartsWith("run", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_job_that_is_not_on_the_fixed_lists_is_refused_and_never_run()
    {
        var host = new FakeHost();
        using var h = Harness(host, Layout());
        await h.EnrollWithTokenAsync();
        var bad = new[] { Job("meshagent", "repair", new string('a', 64)), Job("powershell", "restart"), Job(Rmm, "repair") };
        // A job the agent does not support is not acknowledged: it is reported as failed when it arrives.
        foreach (var job in bad)
        {
            h.Server.EnqueueJob(job);
        }

        await h.Runtime.CheckInOnceAsync(Ct);
        await h.RunJobsAndFlushAsync();

        foreach (var job in bad)
        {
            Assert.Equal(JobStatus.Failed, h.Server.StatusesFor(job.JobId)[^1].Status);
        }

        Assert.Empty(host.Calls);
    }

    [Fact]
    public async Task A_log_collection_job_returns_the_logs_as_diagnostics()
    {
        var layout = Layout();
        Directory.CreateDirectory(Path.GetDirectoryName(layout.EasyPatchLogFile)!);
        File.WriteAllText(layout.EasyPatchLogFile, "patch agent is fine\n");
        using var h = Harness(new FakeHost(), layout);
        await h.EnrollWithTokenAsync();
        var job = AgentHarness.SimpleJob(JobType.CollectLogs);
        await h.DeliverAsync(job);
        await h.RunJobsAndFlushAsync();

        var final = h.Server.StatusesFor(job.JobId)[^1];
        Assert.Equal(JobStatus.Completed, final.Status);
        Assert.Contains("patch agent is fine", final.Diagnostics);
        Assert.Contains("==== easypatch-agent ====", final.Diagnostics);
    }
}
