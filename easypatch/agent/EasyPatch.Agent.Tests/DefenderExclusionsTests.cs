using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using EasyPatch.Agent.Core.Companion;
using EasyPatch.Agent.Core.Defender;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>ADR-0070, slice B: the EasyPatch agent's Defender exclusions. The rules (the record, the state table, what is added and
/// removed, the folder table) run on every system; what talks to Defender and to the file system is faked at the two interfaces.</summary>
public sealed class DefenderExclusionsTests : IDisposable
{
    private const string Install = @"C:\Program Files\EasyPatch Agent";
    private const string Data = @"C:\ProgramData\EasyPatch";
    private const string Exe = Install + @"\EasyPatch.Agent.exe";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "easypatch-defender-tests", Guid.NewGuid().ToString("N"));

    public DefenderExclusionsTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string RecordFile => Path.Combine(_dir, "state", DefenderRecord.FileName);

    private sealed class FakeDefender : IDefenderBackend
    {
        public Dictionary<string, List<string>> Lists { get; } = DefenderKinds.All.ToDictionary(k => k, _ => new List<string>());
        public bool Missing { get; set; }
        public string RunningMode { get; set; } = "Normal";
        public bool AntivirusOn { get; set; } = true;
        public bool RealTimeOn { get; set; } = true;
        public bool DisableLocalAdminMerge { get; set; }
        public bool TamperProtected { get; set; }
        public int AsrRules { get; set; } = 1;
        public bool CfaOn { get; set; } = true;
        public string? NotAvailable { get; set; }
        public bool FailRead { get; set; }
        public bool FailRemove { get; set; }
        public Func<string, string, Exception?>? OnAdd { get; set; }
        public List<string> Calls { get; } = [];
        public string Method => "powershell";

        public Task<DefenderPrefs> ReadAsync(CancellationToken cancellationToken)
        {
            if (FailRead)
            {
                throw new InvalidOperationException("PowerShell failed");
            }

            return Task.FromResult(new DefenderPrefs
            {
                Missing = Missing,
                NotAvailable = NotAvailable,
                Lists = Lists.ToDictionary(p => p.Key, p => (IReadOnlyList<string>)p.Value.ToList()),
                DisableLocalAdminMerge = DisableLocalAdminMerge,
                ControlledFolderAccessOn = CfaOn,
                AsrRules = AsrRules,
                RunningMode = RunningMode,
                AntivirusOn = AntivirusOn,
                ServiceOn = AntivirusOn,
                RealTimeOn = RealTimeOn,
                TamperProtected = TamperProtected,
            });
        }

        public Task AddAsync(string kind, string path, CancellationToken cancellationToken)
        {
            Calls.Add($"add {kind} {path}");
            if (OnAdd?.Invoke(kind, path) is { } error)
            {
                throw error;
            }

            Lists[kind].Add(path);
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string kind, string path, CancellationToken cancellationToken)
        {
            Calls.Add($"remove {kind} {path}");
            if (FailRemove)
            {
                throw new InvalidOperationException("Defender is unreachable");
            }

            Lists[kind].RemoveAll(e => DefenderRecord.Normalize(e) == DefenderRecord.Normalize(path));
            return Task.CompletedTask;
        }
    }

    private sealed class FakeGuard : IFolderGuard
    {
        public Dictionary<string, string> Problems { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Locked { get; } = [];

        public string? Secure(string folder)
        {
            Locked.Add(folder);
            return Check(folder);
        }

        public string? Check(string folder) => Problems.GetValueOrDefault(folder);
    }

    private DefenderExclusions Create(FakeDefender defender, FakeGuard guard) => new(
        new DefenderExclusionsOptions { Folders = [Install, Data], Programs = [Exe], RecordFile = RecordFile, AgentVersion = "9.9.9" },
        defender, guard, NullLogger.Instance);

    // ---- the record -----------------------------------------------------------------------------------------------------------

    [Fact]
    public void The_record_is_the_format_of_the_EasyRMM_agent_and_survives_a_round_trip()
    {
        var record = new DefenderRecord();
        record.Put(new DefenderEntry { Kind = "path", Path = Data, At = new DateTimeOffset(2026, 11, 26, 5, 0, 0, TimeSpan.Zero), AgentVersion = "1.0.0" });
        record.Save(RecordFile);

        using var json = JsonDocument.Parse(File.ReadAllText(RecordFile));
        Assert.Equal(1, json.RootElement.GetProperty("version").GetInt32());
        var entry = json.RootElement.GetProperty("entries")[0];
        Assert.Equal(["kind", "path", "at", "agentVersion"], entry.EnumerateObject().Select(p => p.Name).ToArray());

        var back = DefenderRecord.Load(RecordFile, out var found, out var corrupt);
        Assert.True(found);
        Assert.False(corrupt);
        Assert.True(back.Has("path", Data.ToUpperInvariant() + @"\")); // paths are compared without case or a trailing separator
        Assert.False(back.Has("asr", Data));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"version\":2,\"entries\":[]}")]
    [InlineData("{\"version\":1,\"entries\":[{\"kind\":\"extension\",\"path\":\"x\"}]}")]
    [InlineData("{\"version\":1,\"entries\":[{\"kind\":\"path\",\"path\":\"\"}]}")]
    public void A_file_that_is_not_a_record_is_corrupt(string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(RecordFile)!);
        File.WriteAllText(RecordFile, content);
        DefenderRecord.Load(RecordFile, out var found, out var corrupt);
        Assert.True(found);
        Assert.True(corrupt);
    }

    // ---- add ------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Locks_each_folder_down_then_adds_all_four_kinds_and_records_exactly_what_it_added()
    {
        var defender = new FakeDefender();
        var guard = new FakeGuard();
        var report = await Create(defender, guard).ReconcileAsync(CancellationToken.None);

        Assert.Equal([Install, Data], guard.Locked);
        Assert.Equal([Install, Data], defender.Lists["path"]);
        Assert.Equal([Install, Data], defender.Lists["asr"]);
        Assert.Equal([Exe], defender.Lists["process"]);
        Assert.Equal([Exe], defender.Lists["cfa"]);
        Assert.Equal(DefenderStates.Effective, report.State);
        Assert.All(report.Folders, f => { Assert.True(f.Listed); Assert.True(f.Ours); Assert.Null(f.Reason); });

        var record = DefenderRecord.Load(RecordFile, out _, out _);
        Assert.Equal(6, record.Entries.Count);
        Assert.All(record.Entries, e => Assert.Equal("9.9.9", e.AgentVersion));
    }

    [Fact]
    public async Task Never_excludes_extensions_temp_folders_or_other_programs()
    {
        var defender = new FakeDefender();
        await Create(defender, new FakeGuard()).ReconcileAsync(CancellationToken.None);
        Assert.Equal(6, defender.Calls.Count);
        Assert.All(defender.Calls, c => Assert.True(
            c.EndsWith(Install, StringComparison.Ordinal) || c.EndsWith(Data, StringComparison.Ordinal) || c.EndsWith(Exe, StringComparison.Ordinal), c));
        Assert.All(defender.Calls, c => Assert.Matches("^add (path|process|asr|cfa) ", c));
    }

    [Fact]
    public async Task A_second_run_adds_nothing()
    {
        var defender = new FakeDefender();
        var sut = Create(defender, new FakeGuard());
        await sut.ReconcileAsync(CancellationToken.None);
        defender.Calls.Clear();
        var report = await sut.ReconcileAsync(CancellationToken.None);
        Assert.Empty(defender.Calls);
        Assert.Equal(DefenderStates.Effective, report.State);
    }

    [Fact]
    public async Task An_entry_that_was_already_there_is_not_ours_not_added_again_and_never_removed()
    {
        var defender = new FakeDefender();
        defender.Lists["path"].Add(Data.ToUpperInvariant() + @"\"); // an administrator's, even for the same folder
        var sut = Create(defender, new FakeGuard());
        var report = await sut.ReconcileAsync(CancellationToken.None);

        Assert.DoesNotContain($"add path {Data}", defender.Calls);
        var record = DefenderRecord.Load(RecordFile, out _, out _);
        Assert.False(record.Has("path", Data));
        Assert.True(record.Has("path", Install));
        Assert.False(report.Folders.Single(f => f.Path == Data).Ours);

        var removal = await sut.RemoveAsync(CancellationToken.None);
        Assert.True(removal.RecordDeleted);
        Assert.Single(defender.Lists["path"]); // the administrator's entry survives uninstall
        Assert.Empty(defender.Lists["process"]);
        Assert.Empty(defender.Lists["asr"]);
        Assert.Empty(defender.Lists["cfa"]);
        Assert.False(File.Exists(RecordFile));
    }

    [Fact]
    public async Task The_record_is_written_before_the_add_and_a_refused_add_leaves_no_record_of_it()
    {
        var defender = new FakeDefender { TamperProtected = true };
        defender.OnAdd = (kind, path) =>
        {
            // The entry is already recorded when Defender is asked, so a crash here cannot leave an exclusion nothing will remove.
            if (kind == "path")
            {
                Assert.True(DefenderRecord.Load(RecordFile, out _, out _).Entries.Count > 0);
                return new DefenderRefusedException("Access is denied");
            }

            return null;
        };
        var report = await Create(defender, new FakeGuard()).ReconcileAsync(CancellationToken.None);

        Assert.Equal(DefenderStates.Refused, report.State);
        Assert.Contains("Access is denied", report.Reason, StringComparison.Ordinal);
        Assert.Contains("Tamper Protection", report.Reason, StringComparison.Ordinal);
        Assert.Empty(defender.Lists["path"]);
        Assert.DoesNotContain(DefenderRecord.Load(RecordFile, out _, out _).Entries, e => e.Kind == "path");
    }

    [Fact]
    public async Task A_defender_failure_that_is_not_a_refusal_is_unavailable_and_never_throws()
    {
        var defender = new FakeDefender { OnAdd = (_, _) => new InvalidOperationException("the module failed") };
        var report = await Create(defender, new FakeGuard()).ReconcileAsync(CancellationToken.None);
        Assert.Equal(DefenderStates.Unavailable, report.State);
        Assert.Empty(DefenderRecord.Load(RecordFile, out _, out _).Entries);

        var unreadable = await Create(new FakeDefender { FailRead = true }, new FakeGuard()).ReconcileAsync(CancellationToken.None);
        Assert.Equal(DefenderStates.Unavailable, unreadable.State);
    }

    [Fact]
    public async Task Text_in_place_of_a_list_is_unavailable_with_that_reason_never_a_guess()
    {
        var defender = new FakeDefender { NotAvailable = "N/A: Must be an administrator or have Tamper Protection disabled" };
        var report = await Create(defender, new FakeGuard()).ReconcileAsync(CancellationToken.None);
        Assert.Equal(DefenderStates.Unavailable, report.State);
        Assert.StartsWith("N/A:", report.Reason, StringComparison.Ordinal);
        Assert.Empty(defender.Calls);
    }

    // ---- not applicable -------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("Passive", true, true)]
    [InlineData("SxS Passive Mode", true, true)]
    [InlineData("EDR Block Mode", true, true)]
    [InlineData("Normal", false, true)]
    [InlineData("Normal", true, false)]
    public async Task When_defender_is_not_the_active_antivirus_the_folders_are_locked_nothing_is_added_and_it_is_not_a_failure(string mode, bool antivirus, bool realTime)
    {
        var defender = new FakeDefender { RunningMode = mode, AntivirusOn = antivirus, RealTimeOn = realTime };
        var guard = new FakeGuard();
        var report = await Create(defender, guard).ReconcileAsync(CancellationToken.None);

        Assert.Equal([Install, Data], guard.Locked);
        Assert.Empty(defender.Calls);
        Assert.Equal(DefenderStates.NotApplicable, report.State);
        Assert.NotEmpty(report.Reason!);
        Assert.All(report.Kinds, k => Assert.Equal(DefenderStates.NotApplicable, k.State));
        Assert.Empty(DefenderRecord.Load(RecordFile, out _, out _).Entries);

        // The reconcile adds them if Defender later becomes active.
        defender.RunningMode = "Normal";
        defender.AntivirusOn = true;
        defender.RealTimeOn = true;
        Assert.Equal(DefenderStates.Effective, (await Create(defender, guard).ReconcileAsync(CancellationToken.None)).State);
    }

    [Fact]
    public async Task A_missing_defender_module_is_not_applicable_and_uninstall_just_deletes_the_record()
    {
        var defender = new FakeDefender { Missing = true };
        var sut = Create(defender, new FakeGuard());
        var report = await sut.ReconcileAsync(CancellationToken.None);
        Assert.Equal(DefenderStates.NotApplicable, report.State);
        Assert.Contains("not installed", report.Reason, StringComparison.Ordinal);

        new DefenderRecord { Entries = [new DefenderEntry { Kind = "path", Path = Data }] }.Save(RecordFile);
        var removal = await sut.RemoveAsync(CancellationToken.None);
        Assert.True(removal.RecordDeleted);
        Assert.Empty(defender.Calls);
    }

    // ---- DisableLocalAdminMerge, ASR and CFA ----------------------------------------------------------------------------------

    [Fact]
    public async Task Local_exclusions_ignored_by_policy_are_reported_present_not_effective_and_still_recorded()
    {
        var defender = new FakeDefender { DisableLocalAdminMerge = true };
        var report = await Create(defender, new FakeGuard()).ReconcileAsync(CancellationToken.None);
        Assert.Equal(DefenderStates.PresentNotEffective, report.State);
        Assert.Equal("local exclusions are ignored (DisableLocalAdminMerge)", report.Reason);
        Assert.Equal(6, DefenderRecord.Load(RecordFile, out _, out _).Entries.Count);
    }

    [Fact]
    public async Task Asr_and_controlled_folder_access_that_are_off_are_not_needed_not_a_failure()
    {
        var defender = new FakeDefender { AsrRules = 0, CfaOn = false };
        var report = await Create(defender, new FakeGuard()).ReconcileAsync(CancellationToken.None);
        Assert.Equal(DefenderStates.Effective, report.State);
        Assert.Equal(DefenderStates.NotNeeded, report.Kinds.Single(k => k.Kind == "asr").State);
        Assert.Equal(DefenderStates.NotNeeded, report.Kinds.Single(k => k.Kind == "cfa").State);
        Assert.Equal(DefenderStates.Effective, report.Kinds.Single(k => k.Kind == "path").State);
    }

    // ---- not locked -----------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task A_folder_that_cannot_be_locked_down_is_not_excluded_nor_are_programs_inside_it()
    {
        var defender = new FakeDefender();
        var guard = new FakeGuard();
        guard.Problems[Install] = @"C:\Program Files may be changed by S-1-5-32-545.";
        var report = await Create(defender, guard).ReconcileAsync(CancellationToken.None);

        Assert.Equal(DefenderStates.NotLocked, report.State);
        Assert.Contains("S-1-5-32-545", report.Reason, StringComparison.Ordinal);
        Assert.Equal([Data], defender.Lists["path"]);
        Assert.Equal([Data], defender.Lists["asr"]);
        Assert.Empty(defender.Lists["process"]); // the program is in the folder that could not be locked
        Assert.Empty(defender.Lists["cfa"]);
        Assert.NotNull(report.Folders.Single(f => f.Path == Install).Reason);
        Assert.False(report.Folders.Single(f => f.Path == Install).Listed);
    }

    [Fact]
    public async Task A_folder_that_became_writable_loses_the_exclusions_the_agent_added_for_it()
    {
        var defender = new FakeDefender();
        var guard = new FakeGuard();
        var sut = Create(defender, guard);
        await sut.ReconcileAsync(CancellationToken.None);
        defender.Lists["path"].Add(@"C:\Administrators\Own"); // an administrator's, untouched

        guard.Problems[Data] = "C:\\ProgramData\\EasyPatch\\x may be changed by S-1-1-0.";
        var report = await sut.ReconcileAsync(CancellationToken.None);

        Assert.Equal(DefenderStates.NotLocked, report.State);
        Assert.Equal([Install, @"C:\Administrators\Own"], defender.Lists["path"]);
        Assert.Equal([Install], defender.Lists["asr"]);
        Assert.Equal([Exe], defender.Lists["process"]); // its folder is still locked
        Assert.DoesNotContain(DefenderRecord.Load(RecordFile, out _, out _).Entries, e => e.Path == Data);
    }

    // ---- remove ---------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Remove_takes_out_exactly_the_recorded_entries_one_call_each_then_deletes_the_record()
    {
        var defender = new FakeDefender();
        var sut = Create(defender, new FakeGuard());
        await sut.ReconcileAsync(CancellationToken.None);
        defender.Lists["path"].Add(@"C:\Administrators\Own");
        defender.Calls.Clear();

        var result = await sut.RemoveAsync(CancellationToken.None);

        Assert.Equal(6, result.Removed.Count);
        Assert.Equal(6, defender.Calls.Count(c => c.StartsWith("remove ", StringComparison.Ordinal)));
        Assert.Equal([@"C:\Administrators\Own"], defender.Lists["path"]);
        Assert.True(result.RecordDeleted);
        Assert.False(File.Exists(RecordFile));
    }

    [Fact]
    public async Task A_failed_removal_keeps_the_entry_in_the_record_for_a_retry()
    {
        var defender = new FakeDefender();
        var sut = Create(defender, new FakeGuard());
        await sut.ReconcileAsync(CancellationToken.None);
        defender.FailRemove = true;

        var result = await sut.RemoveAsync(CancellationToken.None);
        Assert.False(result.RecordDeleted);
        Assert.Equal(6, result.Left.Count);
        Assert.Equal(6, DefenderRecord.Load(RecordFile, out _, out _).Entries.Count);

        defender.FailRemove = false;
        Assert.True((await sut.RemoveAsync(CancellationToken.None)).RecordDeleted);
        Assert.All(defender.Lists.Values, l => Assert.Empty(l));

        defender.FailRead = true; // Defender unreachable: nothing is deleted
        new DefenderRecord { Entries = [new DefenderEntry { Kind = "path", Path = Data }] }.Save(RecordFile);
        Assert.False((await sut.RemoveAsync(CancellationToken.None)).RecordDeleted);
        Assert.True(File.Exists(RecordFile));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Without_a_readable_record_only_the_fixed_set_for_folders_that_still_verify_is_removed(bool corrupt)
    {
        var defender = new FakeDefender();
        var guard = new FakeGuard();
        var sut = Create(defender, guard);
        await sut.ReconcileAsync(CancellationToken.None);
        File.Delete(RecordFile);
        if (corrupt)
        {
            File.WriteAllText(RecordFile, "garbage");
        }

        defender.Lists["path"].Add(@"C:\Administrators\Own");
        defender.Lists["process"].Add(@"C:\Tools\other.exe");
        guard.Problems[Data] = "no longer verifies";

        var result = await sut.RemoveAsync(CancellationToken.None);

        // Data does not verify, so nothing of it is touched; Install and its program match the fixed set.
        Assert.Equal([Data, @"C:\Administrators\Own"], defender.Lists["path"]);
        Assert.Equal([Data], defender.Lists["asr"]);
        Assert.Equal([@"C:\Tools\other.exe"], defender.Lists["process"]);
        Assert.Empty(defender.Lists["cfa"]);
        Assert.Equal(4, result.Removed.Count);
        Assert.DoesNotContain(defender.Calls, c => c.Contains('*'));
    }

    // ---- status ---------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Status_changes_nothing()
    {
        var defender = new FakeDefender();
        var guard = new FakeGuard();
        var report = await Create(defender, guard).StatusAsync(CancellationToken.None);
        Assert.Empty(defender.Calls);
        Assert.Empty(guard.Locked);
        Assert.False(File.Exists(RecordFile));
        Assert.Equal(DefenderStates.Refused, report.State); // nothing is listed yet, and nothing was added
    }

    [Fact]
    public async Task The_report_serializes_to_the_shape_of_the_EasyRMM_agents_report()
    {
        var report = await Create(new FakeDefender(), new FakeGuard()).ReconcileAsync(CancellationToken.None);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(report));
        var root = json.RootElement;
        Assert.Equal("effective", root.GetProperty("state").GetString());
        Assert.Equal("9.9.9", root.GetProperty("agentVersion").GetString());
        Assert.Equal(["path", "process", "asr", "cfa"], root.GetProperty("kinds").EnumerateArray().Select(k => k.GetProperty("kind").GetString()).ToArray());
        var folder = root.GetProperty("folders")[0];
        Assert.True(folder.GetProperty("listed").GetBoolean());
        Assert.True(folder.GetProperty("ours").GetBoolean());
        Assert.False(folder.TryGetProperty("reason", out _));
    }

    // ---- the fixed scripts ----------------------------------------------------------------------------------------------------

    [Fact]
    public void The_scripts_are_fixed_text_and_the_path_travels_in_the_environment()
    {
        foreach (var kind in DefenderKinds.All)
        {
            foreach (var verb in (string[])["Add", "Remove"])
            {
                var script = DefenderScripts.ChangeScript(verb, kind)!;
                Assert.Contains($"{verb}-MpPreference -{DefenderKinds.Parameter(kind)} $env:{DefenderScripts.PathVariable}", script, StringComparison.Ordinal);
                Assert.DoesNotContain("C:", script, StringComparison.Ordinal);
                Assert.Contains("MSFT_MpPreference", DefenderScripts.WmiScript(verb, kind), StringComparison.Ordinal);
            }
        }

        Assert.Null(DefenderScripts.ChangeScript("Add", "extension"));
        Assert.Null(DefenderScripts.ChangeScript("Set", "path"));
        Assert.DoesNotContain("ExclusionExtension", DefenderScripts.ReadScript + string.Concat(DefenderKinds.All.Select(k => DefenderKinds.Parameter(k))), StringComparison.Ordinal);
    }

    [Fact]
    public void Defenders_answer_is_read_and_its_refusals_told_from_failures()
    {
        const string answer = """{"missing":false,"path":["C:\\a"],"process":[],"asr":["N/A: Must be an administrator"],"cfa":[],"disableLocalAdminMerge":true,"cfaMode":2,"asrRules":3,"runningMode":"Passive","antivirusEnabled":true,"serviceEnabled":true,"realTimeEnabled":false,"tamperProtected":true}""";
        var prefs = DefenderScripts.ParsePrefs("warning line\n" + answer + "\n");
        Assert.True(prefs.Listed("path", @"c:\A\"));
        Assert.StartsWith("N/A:", prefs.NotAvailable, StringComparison.Ordinal);
        Assert.True(prefs.DisableLocalAdminMerge);
        Assert.True(prefs.ControlledFolderAccessOn);
        Assert.Equal(3, prefs.AsrRules);
        Assert.Equal("Passive", prefs.RunningMode);
        Assert.False(prefs.RealTimeOn);
        Assert.True(prefs.TamperProtected);

        Assert.True(DefenderScripts.ParsePrefs("""{"missing":true}""").Missing);
        Assert.Throws<InvalidDataException>(() => DefenderScripts.ParsePrefs("Get-MpPreference : boom"));
        Assert.True(DefenderScripts.IsRefusal("Add-MpPreference : Access is denied. 0x800106ba"));
        Assert.False(DefenderScripts.IsRefusal("The term 'Add-MpPreference' is not recognized"));
    }

    // ---- the folder table -----------------------------------------------------------------------------------------------------

    [Fact]
    public void Below_an_excluded_folder_only_links_foreign_owners_and_other_writers_are_a_problem()
    {
        const string system = "S-1-5-18", admins = "S-1-5-32-544", users = "S-1-5-32-545", creator = "S-1-3-0", me = "S-1-5-21-1-2-3-1001";
        const uint full = 0x1F01FF, read = 0x120089, append = 0x4;
        FileTrust.AclEntry Allow(string who, uint mask, byte flags = 0) => new(true, flags, mask, who);
        FileTrust.AclEntry[] Clean() => [Allow(system, full), Allow(admins, full)];

        Assert.Null(FileTrust.TreeProblem("f", reparse: false, admins, Clean(), agentSid: null));
        Assert.Null(FileTrust.TreeProblem("f", false, system, [.. Clean(), Allow(users, read), Allow(creator, full)], null));
        Assert.Null(FileTrust.TreeProblem("f", false, me, Clean(), agentSid: me)); // the agent's own account
        Assert.Contains("owned by", FileTrust.TreeProblem("f", false, me, Clean(), agentSid: null), StringComparison.Ordinal);
        Assert.Contains("owned by", FileTrust.TreeProblem("f", false, null, Clean(), null), StringComparison.Ordinal);
        Assert.Contains("link", FileTrust.TreeProblem("f", reparse: true, admins, Clean(), null), StringComparison.Ordinal);
        Assert.Contains("no access list", FileTrust.TreeProblem("f", false, admins, null, null), StringComparison.Ordinal);
        Assert.Contains(users, FileTrust.TreeProblem("f", false, admins, [.. Clean(), Allow(users, append)], null), StringComparison.Ordinal);
        Assert.Contains("S-1-1-0", FileTrust.TreeProblem("f", false, admins, [.. Clean(), Allow("S-1-1-0", 0x10000000)], null), StringComparison.Ordinal);
    }

    // ---- where the agent works ------------------------------------------------------------------------------------------------

    [Fact]
    public void Processes_the_agent_starts_get_the_work_folder_as_TEMP_TMP_and_working_directory()
    {
        var info = new ProcessStartInfo("x");
        AgentFolders.UseWorkDirectory(info, _dir);
        var work = Path.Combine(_dir, "work");
        Assert.Equal(work, info.WorkingDirectory);
        Assert.Equal(work, info.Environment["TEMP"]);
        Assert.Equal(work, info.Environment["TMP"]);
        Assert.True(Directory.Exists(work));

        var msiexec = new ProcessStartInfo("x") { WorkingDirectory = "sys" };
        AgentFolders.UseWorkAsTemp(msiexec, _dir);
        Assert.Equal("sys", msiexec.WorkingDirectory);
        Assert.Equal(work, msiexec.Environment["TMP"]);

        Assert.Equal(Path.Combine(_dir, "bundle", "unenroll"), AgentFolders.BundleDirectory(_dir, AgentFolders.UnenrollBundle));
        Assert.Equal(3, AgentFolders.BundleNames.Distinct().Count()); // one folder per service or command, never shared
    }

    // ---- the package ----------------------------------------------------------------------------------------------------------

    [Fact]
    public void The_package_creates_locks_verifies_and_excludes_before_it_lays_down_files_and_sets_the_extract_folder_for_the_service_only()
    {
        var wxs = File.ReadAllText(Path.Combine(RepositoryRoot(), "agent", "Installer", "Package.wxs"));

        Assert.Contains("<Custom Action=\"DefenderPreExclude\" After=\"CreateFolders\"", wxs, StringComparison.Ordinal);
        Assert.Contains("<Custom Action=\"DefenderExclude\" After=\"ServiceBundleEnvironment\"", wxs, StringComparison.Ordinal);
        Assert.Contains("<Custom Action=\"UnenrollAgent\" After=\"DefenderRemove\"", wxs, StringComparison.Ordinal);
        Assert.Contains("<Custom Action=\"DefenderRemove\" After=\"StopServices\" Condition=\"REMOVE~=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE\"", wxs, StringComparison.Ordinal);

        // Every action that runs a Defender step ignores its own failure: it never fails an install or an uninstall.
        foreach (var id in (string[])["DefenderPreExclude", "DefenderExclude", "DefenderRemove", "ServiceBundleEnvironment"])
        {
            var action = Regex.Match(wxs, $"<CustomAction Id=\"{id}\"[^>]*>", RegexOptions.Singleline).Value;
            Assert.Contains("Return=\"ignore\"", action, StringComparison.Ordinal);
        }

        // The variable is set in the service's own Environment value and in each command's own environment; never machine-wide.
        Assert.Contains(@"Services\EasyPatchAgent /v Environment /t REG_MULTI_SZ", wxs, StringComparison.Ordinal);
        Assert.DoesNotContain(@"Session Manager\Environment", wxs, StringComparison.Ordinal);
        foreach (var name in AgentFolders.BundleNames)
        {
            Assert.Contains($"{AgentFolders.BundleExtractVariable}=[DATAFOLDER]bundle\\{name}", wxs, StringComparison.Ordinal);
        }

        // The pre-script: fixed paths, no extension, no process, no machine-wide switch, no double quote.
        var script = Regex.Match(wxs, "<Property Id=\"DefenderPreScript\" Value=\"(?<v>[^\"]*)\"", RegexOptions.Singleline).Groups["v"].Value;
        Assert.NotEmpty(script);
        Assert.DoesNotContain("ExclusionExtension", script, StringComparison.Ordinal);
        Assert.DoesNotContain("ExclusionProcess", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Set-MpPreference", script, StringComparison.Ordinal);
        Assert.Contains("Add-MpPreference", script, StringComparison.Ordinal);
        Assert.True(script.IndexOf("Lock $pd", StringComparison.Ordinal) < script.IndexOf("Problem $d", StringComparison.Ordinal));
        Assert.True(script.IndexOf("Problem $d", StringComparison.Ordinal) < script.IndexOf("Add-MpPreference", StringComparison.Ordinal));
        Assert.True(script.IndexOf("Save;", StringComparison.Ordinal) < script.IndexOf("Add-MpPreference", StringComparison.Ordinal)); // the record first

        // The program folder and the work and extract folders are locked down in the package as well.
        Assert.Contains("<Component Id=\"InstallFolder\" Directory=\"INSTALLFOLDER\"", wxs, StringComparison.Ordinal);
        foreach (var folder in (string[])["WorkFolder", "BundleServiceFolder", "BundleUnenrollFolder", "BundleDefenderFolder"])
        {
            Assert.Contains($"<Component Id=\"{folder}\"", wxs, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void The_winget_and_msiexec_runners_set_TEMP_and_TMP_to_the_work_folder()
    {
        var platform = Path.Combine(RepositoryRoot(), "agent", "EasyPatch.Agent", "Platform");
        Assert.Contains("AgentFolders.UseWorkDirectory(info", File.ReadAllText(Path.Combine(platform, "WingetProcessRunner.cs")), StringComparison.Ordinal);
        Assert.DoesNotContain("GetTempPath", File.ReadAllText(Path.Combine(platform, "WingetProcessRunner.cs")), StringComparison.Ordinal);
        foreach (var file in (string[])["WindowsAgentInstaller.cs", "WindowsAgentUninstaller.cs"])
        {
            Assert.Contains("AgentFolders.UseWorkAsTemp(info", File.ReadAllText(Path.Combine(platform, file)), StringComparison.Ordinal);
        }
    }

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EasyPatch.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("The EasyPatch solution folder was not found.");
    }
}
