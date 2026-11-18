using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Scanning;
using EasyPatch.Contracts.Agent;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>What a pending restart is for: the registry signals Windows uses, read into <see cref="RebootDetails"/>.</summary>
public sealed class RebootDetailsTests
{
    [Fact]
    public void Files_queued_only_for_deletion_do_not_need_a_restart()
    {
        var cleanup = WindowsRebootSignals.FileOperations(
        [
            @"*1\??\C:\Users\alice\AppData\Local\Temp\~nsuA.tmp\Un_A.exe", "",
            @"\??\C:\Windows\System32\drivers\SET9947.tmp", "",
        ]);
        Assert.False(WindowsRebootSignals.NeedRestart(cleanup));
        Assert.False(WindowsRebootSignals.NeedRestart([]));

        var replacement = WindowsRebootSignals.FileOperations(
        [
            @"\??\C:\Windows\Temp\a.tmp", "",
            @"\??\C:\Program Files\Contoso\contoso.dll.new", @"!\??\C:\Program Files\Contoso\contoso.dll",
        ]);
        Assert.True(WindowsRebootSignals.NeedRestart(replacement));
    }

    [Fact]
    public void Pending_file_renames_become_deletes_and_replacements_without_user_names()
    {
        // REG_MULTI_SZ pairs: source, destination (empty destination: delete the source at the restart).
        string[] value =
        [
            @"\??\C:\Users\alice\AppData\Local\Temp\setup-1234\helper.dll", "",
            @"\??\C:\Program Files\Contoso\Agent\contoso.dll.new", @"!\??\C:\Program Files\Contoso\Agent\contoso.dll",
            @"\??\C:\Windows\Temp\a.tmp", "",
            @"\??\C:\Windows\Temp\a.tmp", "",
            "", "",
            @"\??\C:\Windows\System32\drivers\odd.sys",
        ];

        var operations = WindowsRebootSignals.FileOperations(value);

        Assert.Equal(
        [
            new PendingFileOperation { Action = PendingFileOperation.Delete, Path = @"C:\Users\*\AppData\Local\Temp\setup-1234\helper.dll" },
            new PendingFileOperation { Action = PendingFileOperation.Replace, Path = @"C:\Program Files\Contoso\Agent\contoso.dll" },
            new PendingFileOperation { Action = PendingFileOperation.Delete, Path = @"C:\Windows\Temp\a.tmp" },
            new PendingFileOperation { Action = PendingFileOperation.Delete, Path = @"C:\Windows\System32\drivers\odd.sys" },
        ], operations);
        Assert.Empty(WindowsRebootSignals.FileOperations(null));

        // As Windows writes them on a real computer: "*1" / "*2" markers and 8.3 profile names.
        Assert.Equal(
        [
            new PendingFileOperation { Action = PendingFileOperation.Delete, Path = @"C:\Users\*\AppData\Local\Temp\~nsuA.tmp\Un_A.exe" },
            new PendingFileOperation { Action = PendingFileOperation.Delete, Path = @"C:\Users\*\AppData\Local\Temp\_iu14D2N.tmp" },
            new PendingFileOperation { Action = PendingFileOperation.Delete, Path = @"C:\Windows\System32\drivers\SET9947.tmp" },
        ], WindowsRebootSignals.FileOperations(
        [
            @"*1\??\C:\Users\paul.mataruso.CONTOSO\AppData\Local\Temp\~nsuA.tmp\Un_A.exe", "",
            @"*2\??\C:\Users\PAULMA~1.CON\AppData\Local\Temp\_iu14D2N.tmp", "",
            @"*1\??\C:\Windows\System32\drivers\SET9947.tmp", "",
        ]));
        Assert.Equal(@"\\server\share\Users\*\x.dll", WindowsRebootSignals.CleanPath(@"\??\UNC\server\share\Users\carol\x.dll"));
        Assert.Equal(@"C:\x.dll", WindowsRebootSignals.CleanPath(@"!*1@\\?\C:\x.dll"));
        Assert.Equal(@"D:\Documents and Settings\*\x.txt", WindowsRebootSignals.CleanPath(@"\??\D:\Documents and Settings\bob\x.txt"));
    }

    [Fact]
    public void Update_ids_and_servicing_packages_are_read_from_key_names()
    {
        var id = Guid.NewGuid();
        Assert.Equal([id], WindowsRebootSignals.UpdateIds([id.ToString(), "{" + id + "}", "Mandatory", "", "not-a-guid"]));

        var packages = WindowsRebootSignals.Packages(
        [
            "Package_for_KB5044284~31bf3856ad364e35~amd64~~26100.2033.1.4",
            "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.2314.1.10",
            "Microsoft-Windows-Foo-Package~31bf3856ad364e35~amd64~~10.0.26100.1",
            "PackagesPending",
            "1",
        ]);
        Assert.Equal(3, packages.Count);

        var details = new RebootDetails { ServicingPackages = packages };
        Assert.Equal(["KB5044284"], details.ServicingKbNumbers());
        Assert.True(RebootDetails.NamesKb(packages[0]));
        Assert.False(RebootDetails.NamesKb(packages[1]));
    }

    [Fact]
    public void Details_are_capped_and_cleaned()
    {
        var details = new RebootDetails
        {
            WindowsUpdateIds = [.. Enumerable.Range(0, 80).Select(_ => Guid.NewGuid()), Guid.Empty],
            ServicingPackages = ["Package_for_KB1234567~x~y~z", "package_for_kb1234567~X~Y~Z", " ", "bad\u0001name~a~b~c"],
            FileOperations =
            [
                .. Enumerable.Range(0, 40).Select(i => new PendingFileOperation { Action = "Delete", Path = $@"C:\Temp\{i}.tmp" }),
                new PendingFileOperation { Action = "Format", Path = new string('x', 400) },
            ],
            FileOperationCount = 0,
        }.Sanitized();

        Assert.Equal(RebootDetails.MaxUpdates, details.WindowsUpdateIds.Count);
        Assert.Equal(["Package_for_KB1234567~x~y~z", "badname~a~b~c"], details.ServicingPackages);
        Assert.Equal(RebootDetails.MaxFileOperations, details.FileOperations.Count);
        Assert.Equal(41, details.FileOperationCount);
        Assert.False(details.IsEmpty);
        Assert.True(new RebootDetails().Sanitized().IsEmpty);

        // The server cleans what an agent sends, too: no user names are stored.
        var raw = new RebootDetails
        {
            FileOperations = [new PendingFileOperation { Action = "Delete", Path = @"*1\??\C:\Users\dave\AppData\Local\Temp\x.tmp" }],
        }.Sanitized();
        Assert.Equal(@"C:\Users\*\AppData\Local\Temp\x.tmp", Assert.Single(raw.FileOperations).Path);
        Assert.DoesNotContain("isEmpty", System.Text.Json.JsonSerializer.Serialize(raw, EasyPatch.Contracts.Json.ContractJson.Options), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_composite_detector_merges_the_details_of_each_signal()
    {
        var first = Guid.NewGuid();
        var detector = new CompositeRebootDetector(
        [
            new Fixed(new RebootStatus(true, ["Windows Update (RebootRequired)"], new RebootDetails { WindowsUpdateIds = [first] })),
            new Fixed(new RebootStatus(true, ["Pending file rename operations"], new RebootDetails
            {
                FileOperations = [new PendingFileOperation { Action = "Delete", Path = @"C:\Windows\Temp\a.tmp" }],
                FileOperationCount = 1,
            })),
            new Fixed(new RebootStatus(true, ["Windows Update (SystemInfo.RebootRequired)"])),
            new Fixed(new RebootStatus(false, [], new RebootDetails { WindowsUpdateIds = [Guid.NewGuid()] })),
        ]);

        var status = await detector.DetectAsync(CancellationToken.None);

        Assert.True(status.Pending);
        Assert.Equal(3, status.Reasons.Count);
        Assert.Equal([first], status.Details!.WindowsUpdateIds);
        Assert.Single(status.Details.FileOperations);

        var withoutDetails = await new CompositeRebootDetector([new Fixed(new RebootStatus(true, ["Pending computer rename"]))]).DetectAsync(CancellationToken.None);
        Assert.Null(withoutDetails.Details);
    }

    private sealed class Fixed(RebootStatus status) : IRebootDetector
    {
        public Task<RebootStatus> DetectAsync(CancellationToken cancellationToken) => Task.FromResult(status);
    }
}
