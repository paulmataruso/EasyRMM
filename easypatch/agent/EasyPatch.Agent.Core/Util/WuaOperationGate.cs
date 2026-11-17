namespace EasyPatch.Agent.Core.Util;

/// <summary>
/// Serializes Windows Update operations: at most one scan or install runs at a time, so scheduled scans never
/// overlap an installation and two installations never run concurrently.
/// </summary>
public sealed class WuaOperationGate : IDisposable
{
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    public bool IsBusy => _semaphore.CurrentCount == 0;

    public bool TryEnter() => _semaphore.Wait(0);

    public Task EnterAsync(CancellationToken cancellationToken) => _semaphore.WaitAsync(cancellationToken);

    public void Exit() => _semaphore.Release();

    public void Dispose() => _semaphore.Dispose();
}
