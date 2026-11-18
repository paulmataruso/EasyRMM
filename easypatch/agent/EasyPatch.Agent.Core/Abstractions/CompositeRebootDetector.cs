using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace EasyPatch.Agent.Core.Abstractions;

/// <summary>Combines several reboot signals (registry, WUA SystemInfo, …); a failing detector is ignored.</summary>
public sealed class CompositeRebootDetector : IRebootDetector
{
    private readonly IReadOnlyList<IRebootDetector> _detectors;
    private readonly ILogger _logger;

    public CompositeRebootDetector(IEnumerable<IRebootDetector> detectors, ILogger<CompositeRebootDetector>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(detectors);
        _detectors = detectors.ToList();
        _logger = (ILogger?)logger ?? NullLogger.Instance;
    }

    public async Task<RebootStatus> DetectAsync(CancellationToken cancellationToken)
    {
        var reasons = new List<string>();
        var details = new List<RebootDetails>();
        foreach (var detector in _detectors)
        {
            try
            {
                var status = await detector.DetectAsync(cancellationToken);
                if (status.Pending)
                {
                    reasons.AddRange(status.Reasons);
                    if (status.Details is { } d)
                    {
                        details.Add(d);
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "Reboot detector {Detector} failed.", detector.GetType().Name);
            }
        }

        var distinct = reasons.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (distinct.Count == 0)
        {
            return RebootStatus.None;
        }

        var merged = new RebootDetails
        {
            WindowsUpdateIds = details.SelectMany(d => d.WindowsUpdateIds).ToList(),
            ServicingPackages = details.SelectMany(d => d.ServicingPackages).ToList(),
            FileOperations = details.SelectMany(d => d.FileOperations).ToList(),
            FileOperationCount = details.Sum(d => d.FileOperationCount),
        }.Sanitized();
        return new RebootStatus(true, distinct, merged.IsEmpty ? null : merged);
    }
}
