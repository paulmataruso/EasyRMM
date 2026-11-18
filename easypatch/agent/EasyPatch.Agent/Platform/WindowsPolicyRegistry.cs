using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Policy;
using Microsoft.Win32;

namespace EasyPatch.Agent.Platform;

/// <summary>The Windows Update policy values under HKLM (64-bit view). Only the two keys in
/// <see cref="WindowsUpdatePolicyRegistry"/> are opened for writing.</summary>
internal sealed class WindowsPolicyRegistry : IPolicyRegistry
{
    private const string MdmUpdateKeyPath = @"SOFTWARE\Microsoft\PolicyManager\current\device\Update";

    public PolicyRegistryValue Read(PolicyRegistryKey key, string name)
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var subKey = root.OpenSubKey(WindowsUpdatePolicyRegistry.KeyPath(key), writable: false);
        if (subKey is null || !subKey.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return new PolicyRegistryValue(key, name);
        }

        var kind = subKey.GetValueKind(name);
        var value = subKey.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return kind switch
        {
            RegistryValueKind.DWord when value is int dword => new PolicyRegistryValue(key, name, DWord: dword),
            RegistryValueKind.String when value is string text => new PolicyRegistryValue(key, name, Text: text),
            _ => new PolicyRegistryValue(key, name, Text: $"<{kind}>"),
        };
    }

    public void Write(PolicyRegistryValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        if (value.IsAbsent)
        {
            using var existing = root.OpenSubKey(value.Path, writable: true);
            existing?.DeleteValue(value.Name, throwOnMissingValue: false);
            return;
        }

        using var subKey = root.CreateSubKey(value.Path, writable: true)
            ?? throw new InvalidOperationException($@"Could not open HKLM\{value.Path}.");
        if (value.DWord is { } dword)
        {
            subKey.SetValue(value.Name, dword, RegistryValueKind.DWord);
        }
        else
        {
            subKey.SetValue(value.Name, value.Text!, RegistryValueKind.String);
        }
    }

    public bool MdmUpdatePoliciesPresent()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = root.OpenSubKey(MdmUpdateKeyPath, writable: false);
        return key is not null && key.GetValueNames().Any(n => !n.EndsWith("_ProviderSet", StringComparison.OrdinalIgnoreCase) &&
                                                             !n.EndsWith("_WinningProvider", StringComparison.OrdinalIgnoreCase));
    }
}
