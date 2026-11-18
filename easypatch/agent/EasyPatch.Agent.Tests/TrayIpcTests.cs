using System.Buffers.Binary;
using System.IO.Pipes;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Ipc;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>The service side of the tray pipe: framing limits and the only inputs a tray can give.</summary>
public sealed class TrayIpcTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public void Signed_in_users_may_open_the_pipe_but_not_serve_it()
    {
        // Everything the tray requests is granted to interactive users...
        Assert.Equal(TrayFrames.ClientAccess, TrayFrames.ClientAccess & TrayFrames.InteractiveUserAccess);

        // ...but not the right to create pipe instances (or to change the pipe's security).
        const PipeAccessRights serverRights = PipeAccessRights.CreateNewInstance | PipeAccessRights.ChangePermissions |
                                              PipeAccessRights.TakeOwnership | PipeAccessRights.Delete;
        Assert.Equal((PipeAccessRights)0, TrayFrames.InteractiveUserAccess & serverRights);

        // GENERIC_READ | GENERIC_WRITE maps to FILE_GENERIC_READ | FILE_GENERIC_WRITE, which includes FILE_APPEND_DATA
        // (= create pipe instance on a pipe). A tray asking for it would be refused, which is why it asks for ClientAccess.
        const PipeAccessRights genericReadWrite = (PipeAccessRights)0x12019F;
        Assert.NotEqual(genericReadWrite, genericReadWrite & TrayFrames.InteractiveUserAccess);
        Assert.Equal((PipeAccessRights)0, TrayFrames.ClientAccess & PipeAccessRights.CreateNewInstance);
    }

    [Fact]
    public async Task Frames_round_trip_and_bad_frames_are_rejected()
    {
        using var stream = new MemoryStream();
        var message = new TrayMessage { Type = TrayMessageType.Notice, Notice = new UserNotice { Preset = UserMessagePreset.SaveYourWork } };
        await TrayFrames.WriteAsync(stream, message, Ct);
        stream.Position = 0;
        Assert.Equal(message, await TrayFrames.ReadAsync(stream, TrayFrames.MaxRequestBytes, Ct));
        Assert.Null(await TrayFrames.ReadAsync(stream, TrayFrames.MaxRequestBytes, Ct)); // clean end of stream

        const int max = TrayFrames.MaxRequestBytes;
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.ReadAsync(Frame(max + 1, []), max, Ct));
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.ReadAsync(Frame(TrayFrames.MaxFrameBytes + 1, []), int.MaxValue, Ct));
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.ReadAsync(Frame(0, []), max, Ct));
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.ReadAsync(Frame(-1, []), max, Ct));
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.ReadAsync(Frame(100, "{\"type\""u8.ToArray()), max, Ct));
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.ReadAsync(Frame(5, "{oops"u8.ToArray()), max, Ct));
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.ReadAsync(new MemoryStream([1, 0]), max, Ct));
        var unknown = "{\"type\":\"formatDisk\"}"u8.ToArray();
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.ReadAsync(Frame(unknown.Length, unknown), max, Ct));

        // The service may send the tray more than a tray may send the service (the log), but not without limit.
        var log = new TrayMessage { Type = TrayMessageType.Log, Log = Enumerable.Range(0, 100).Select(i => new TrayLogEntry(DateTimeOffset.UtcNow, TrayLogLevel.Information, new string('x', 300))).ToList() };
        using var large = new MemoryStream();
        await TrayFrames.WriteAsync(large, log, Ct);
        large.Position = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.ReadAsync(large, TrayFrames.MaxRequestBytes, Ct));
        large.Position = 0;
        Assert.Equal(100, (await TrayFrames.ReadAsync(large, TrayFrames.MaxFrameBytes, Ct))!.Log!.Count);

        var huge = new TrayMessage { Type = TrayMessageType.Prompt, Prompt = new RestartPrompt { JobId = Guid.NewGuid(), Kind = RestartPromptKind.Prompt, PostponeOptions = Enumerable.Range(0, 60_000).ToList() } };
        await Assert.ThrowsAsync<InvalidDataException>(() => TrayFrames.WriteAsync(new MemoryStream(), huge, Ct));
    }

    [Fact]
    public async Task A_tray_can_only_answer_the_current_restart_prompt_with_an_offered_choice()
    {
        var pipeName = "easypatch-test-" + Guid.NewGuid().ToString("N");
        var broker = new TrayBroker(() => [7], NullLogger<TrayBroker>.Instance);
        await using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        var connecting = server.WaitForConnectionAsync(Ct);
        await client.ConnectAsync(Ct);
        await connecting;

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        var serving = broker.ServeAsync(server, sessionId: 7, stop.Token);

        // A new tray receives the current status and prompt straight away.
        Assert.Equal(TrayMessageType.Status, (await ReadAsync(client)).Type);
        var initial = await ReadAsync(client);
        Assert.Equal(TrayMessageType.Prompt, initial.Type);
        Assert.Null(initial.Prompt);
        Assert.Equal(new UserSessionInfo { SignedInUsers = 1, TrayConnected = 1 }, broker.GetSessions());

        // Nothing to answer yet.
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.RestartNow, JobId = Guid.NewGuid() }, Ct);

        var jobId = Guid.NewGuid();
        broker.SetRestartPrompt(new RestartPrompt { JobId = jobId, Kind = RestartPromptKind.Prompt, PostponeOptions = [60, 240] });
        Assert.Equal(jobId, (await ReadAsync(client)).Prompt!.JobId);

        // Ignored: wrong job, a choice that was not offered, and messages only the service may send.
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.RestartNow, JobId = Guid.NewGuid() }, Ct);
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.Postpone, JobId = jobId, Minutes = 1440 }, Ct);
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.Postpone, JobId = jobId }, Ct);
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.Exit, JobId = jobId }, Ct);
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.Notice, JobId = jobId, Notice = new UserNotice { Preset = UserMessagePreset.SaveYourWork } }, Ct);

        // Accepted.
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.Postpone, JobId = jobId, Minutes = 240 }, Ct);
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.RestartNow, JobId = jobId }, Ct);

        var responses = await WaitForResponsesAsync(broker, 2);
        Assert.Equal(
            [new RestartPromptResponse(jobId, false, 240, 7), new RestartPromptResponse(jobId, true, null, 7)],
            responses);

        // Messages reach the tray; a countdown cannot be postponed.
        Assert.Equal(1, broker.Notify(new UserNotice { Preset = UserMessagePreset.UpdatesInstalling }));
        Assert.Equal(UserMessagePreset.UpdatesInstalling, (await ReadAsync(client)).Notice!.Preset);
        broker.SetRestartPrompt(new RestartPrompt { JobId = jobId, Kind = RestartPromptKind.Countdown, RestartAt = DateTimeOffset.UtcNow.AddMinutes(5) });
        Assert.Equal(RestartPromptKind.Countdown, (await ReadAsync(client)).Prompt!.Kind);
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.Postpone, JobId = jobId, Minutes = 60 }, Ct);
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.RestartNow, JobId = jobId }, Ct);
        Assert.True(Assert.Single(await WaitForResponsesAsync(broker, 1)).RestartNow);

        // A malformed frame disconnects the tray.
        var bad = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(bad, 1_000_000);
        await client.WriteAsync(bad, Ct);
        await serving.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.Empty(broker.ConnectedSessions);
        Assert.Equal(0, broker.Notify(new UserNotice { Preset = UserMessagePreset.SaveYourWork }));
    }

    [Fact]
    public async Task Status_window_requests_are_rate_limited_and_answered_only_to_the_asking_tray()
    {
        var handler = new RecordingHandler();
        var entries = new List<TrayLogEntry>
        {
            new(DateTimeOffset.UtcNow.AddMinutes(-2), TrayLogLevel.Information, "Scan completed."),
            new(DateTimeOffset.UtcNow.AddMinutes(-1), TrayLogLevel.Warning, "Server unreachable."),
        };
        var broker = new TrayBroker(() => [7], NullLogger<TrayBroker>.Instance, () => entries);
        await using var pair = await PipePair.ConnectAsync(broker, sessionId: 7);
        var client = pair.Client;
        await ReadAsync(client); // status
        await ReadAsync(client); // prompt

        // Before the agent runtime exists, requests are answered without effect.
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.CheckIn }, Ct);
        var starting = await ReadAsync(client);
        Assert.Equal(TrayMessageType.RequestResult, starting.Type);
        Assert.False(starting.Result!.Accepted);
        Assert.Empty(handler.Calls);

        broker.SetRequestHandler(handler);
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.CheckForUpdates }, Ct);
        var answer = await ReadAsync(client);
        Assert.Equal(UserRequestKind.CheckForUpdates, answer.Request);
        Assert.Equal(new UserRequestResult(true, "ok CheckForUpdates"), answer.Result);
        Assert.Equal([(UserRequestKind.CheckForUpdates, 7)], handler.Calls);

        // The same request again at once: "please wait", without reaching the agent.
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.CheckForUpdates, JobId = Guid.NewGuid(), Minutes = 5 }, Ct);
        var again = await ReadAsync(client);
        Assert.False(again.Result!.Accepted);
        Assert.Single(handler.Calls);

        // The log goes to the tray that asked; asking again at once is ignored (the next answer is something else).
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.GetLog }, Ct);
        var log = await ReadAsync(client);
        Assert.Equal(TrayMessageType.Log, log.Type);
        Assert.Equal(entries, log.Log!.ToList());
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.GetLog }, Ct);
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.CheckIn }, Ct);
        var next = await ReadAsync(client);
        Assert.Equal(TrayMessageType.RequestResult, next.Type);
        Assert.Equal(UserRequestKind.CheckIn, next.Request);
        Assert.Equal(2, handler.Calls.Count);

        // A request larger than a tray may send closes the connection.
        await TrayFrames.WriteAsync(client, new TrayMessage { Type = TrayMessageType.CheckIn, Log = log.Log!.Concat(Enumerable.Repeat(log.Log![0] with { Message = new string('y', 300) }, 100)).ToList() }, Ct);
        await pair.Serving.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        Assert.Empty(broker.ConnectedSessions);
    }

    [Fact]
    public async Task A_long_log_is_cut_to_its_newest_entries()
    {
        var start = DateTimeOffset.UtcNow.AddDays(-1);
        var entries = Enumerable.Range(0, 3000).Select(i => new TrayLogEntry(start.AddSeconds(i), TrayLogLevel.Information, $"{i:D5} " + new string('m', 290))).ToList();
        var broker = new TrayBroker(() => [3], NullLogger<TrayBroker>.Instance, () => entries);
        await using var pair = await PipePair.ConnectAsync(broker, sessionId: 3);
        await ReadAsync(pair.Client);
        await ReadAsync(pair.Client);

        await TrayFrames.WriteAsync(pair.Client, new TrayMessage { Type = TrayMessageType.GetLog }, Ct);
        var log = (await ReadAsync(pair.Client)).Log!;
        Assert.InRange(log.Count, 100, entries.Count - 1);
        Assert.Equal(entries[^1], log[^1]);
        Assert.Equal(entries.Skip(entries.Count - log.Count).ToList(), log.ToList());
    }

    private sealed class RecordingHandler : IUserRequestHandler
    {
        public List<(UserRequestKind Kind, int SessionId)> Calls { get; } = [];

        public UserRequestResult Handle(UserRequestKind kind, int sessionId)
        {
            Calls.Add((kind, sessionId));
            return new UserRequestResult(true, $"ok {kind}");
        }
    }

    private sealed class PipePair : IAsyncDisposable
    {
        private readonly CancellationTokenSource _stop;
        private readonly NamedPipeServerStream _server;

        private PipePair(NamedPipeServerStream server, NamedPipeClientStream client, CancellationTokenSource stop, Task serving)
        {
            _server = server;
            Client = client;
            _stop = stop;
            Serving = serving;
        }

        public NamedPipeClientStream Client { get; }
        public Task Serving { get; }

        public static async Task<PipePair> ConnectAsync(TrayBroker broker, int sessionId)
        {
            var name = "easypatch-test-" + Guid.NewGuid().ToString("N");
            var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            var connecting = server.WaitForConnectionAsync(Ct);
            await client.ConnectAsync(Ct);
            await connecting;
            var stop = CancellationTokenSource.CreateLinkedTokenSource(Ct);
            return new PipePair(server, client, stop, broker.ServeAsync(server, sessionId, stop.Token));
        }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            try
            {
                await Serving.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or TimeoutException)
            {
            }

            await Client.DisposeAsync();
            await _server.DisposeAsync();
            _stop.Dispose();
        }
    }

    private static MemoryStream Frame(int length, byte[] body)
    {
        var bytes = new byte[4 + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, length);
        body.CopyTo(bytes, 4);
        return new MemoryStream(bytes);
    }

    private static async Task<TrayMessage> ReadAsync(Stream stream)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        return await TrayFrames.ReadAsync(stream, TrayFrames.MaxFrameBytes, timeout.Token) ?? throw new EndOfStreamException();
    }

    private static async Task<List<RestartPromptResponse>> WaitForResponsesAsync(TrayBroker broker, int count)
    {
        var all = new List<RestartPromptResponse>();
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (all.Count < count && DateTime.UtcNow < deadline)
        {
            all.AddRange(broker.TakeResponses());
            await Task.Delay(20, Ct);
        }

        await Task.Delay(100, Ct); // anything that should have been ignored would have arrived by now
        all.AddRange(broker.TakeResponses());
        return all;
    }
}
