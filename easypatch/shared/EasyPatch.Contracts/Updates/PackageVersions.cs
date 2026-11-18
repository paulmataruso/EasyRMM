namespace EasyPatch.Contracts.Updates;

/// <summary>Debian package version ordering (deb-version(7): <c>[epoch:]upstream[-revision]</c>, <c>~</c> sorts first).</summary>
public static class DebianVersion
{
    public static int Compare(string? a, string? b)
    {
        Split(a ?? string.Empty, out var epochA, out var upstreamA, out var revisionA);
        Split(b ?? string.Empty, out var epochB, out var upstreamB, out var revisionB);
        if (epochA != epochB)
        {
            return epochA.CompareTo(epochB);
        }

        var upstream = CompareFragment(upstreamA, upstreamB);
        return upstream != 0 ? upstream : CompareFragment(revisionA, revisionB);
    }

    private static void Split(string version, out long epoch, out string upstream, out string revision)
    {
        version = version.Trim();
        epoch = 0;
        var colon = version.IndexOf(':', StringComparison.Ordinal);
        if (colon > 0 && long.TryParse(version.AsSpan(0, colon), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var e))
        {
            epoch = e;
            version = version[(colon + 1)..];
        }

        var hyphen = version.LastIndexOf('-');
        if (hyphen >= 0)
        {
            upstream = version[..hyphen];
            revision = version[(hyphen + 1)..];
        }
        else
        {
            upstream = version;
            revision = string.Empty;
        }
    }

    /// <summary>dpkg's verrevcmp: alternating non-digit parts (letters before non-letters, '~' before everything,
    /// even the end of the string) and numeric parts.</summary>
    private static int CompareFragment(string a, string b)
    {
        int i = 0, j = 0;
        while (i < a.Length || j < b.Length)
        {
            var firstDiff = 0;
            while ((i < a.Length && !char.IsAsciiDigit(a[i])) || (j < b.Length && !char.IsAsciiDigit(b[j])))
            {
                var ac = i < a.Length ? Order(a[i]) : 0;
                var bc = j < b.Length ? Order(b[j]) : 0;
                if (ac != bc)
                {
                    return ac - bc;
                }

                i++;
                j++;
            }

            while (i < a.Length && a[i] == '0')
            {
                i++;
            }

            while (j < b.Length && b[j] == '0')
            {
                j++;
            }

            while (i < a.Length && char.IsAsciiDigit(a[i]) && j < b.Length && char.IsAsciiDigit(b[j]))
            {
                if (firstDiff == 0)
                {
                    firstDiff = a[i] - b[j];
                }

                i++;
                j++;
            }

            if (i < a.Length && char.IsAsciiDigit(a[i]))
            {
                return 1;
            }

            if (j < b.Length && char.IsAsciiDigit(b[j]))
            {
                return -1;
            }

            if (firstDiff != 0)
            {
                return firstDiff;
            }
        }

        return 0;
    }

    private static int Order(char c) => c switch
    {
        '~' => -1,
        _ when char.IsAsciiDigit(c) => 0,
        _ when char.IsAsciiLetter(c) => c,
        _ => c + 256,
    };
}

/// <summary>RPM version ordering (<c>[epoch:]version-release</c> compared with rpmvercmp, <c>~</c> and <c>^</c> handled).</summary>
public static class RpmVersion
{
    public static int Compare(string? a, string? b)
    {
        Split(a ?? string.Empty, out var epochA, out var versionA, out var releaseA);
        Split(b ?? string.Empty, out var epochB, out var versionB, out var releaseB);
        if (epochA != epochB)
        {
            return epochA.CompareTo(epochB);
        }

        var version = VerCmp(versionA, versionB);
        if (version != 0 || releaseA.Length == 0 || releaseB.Length == 0)
        {
            return version;
        }

        return VerCmp(releaseA, releaseB);
    }

    private static void Split(string evr, out long epoch, out string version, out string release)
    {
        evr = evr.Trim();
        epoch = 0;
        var colon = evr.IndexOf(':', StringComparison.Ordinal);
        if (colon > 0 && long.TryParse(evr.AsSpan(0, colon), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var e))
        {
            epoch = e;
            evr = evr[(colon + 1)..];
        }

        var hyphen = evr.LastIndexOf('-');
        if (hyphen >= 0)
        {
            version = evr[..hyphen];
            release = evr[(hyphen + 1)..];
        }
        else
        {
            version = evr;
            release = string.Empty;
        }
    }

    /// <summary>rpmvercmp from rpm's lib/rpmvercmp.c.</summary>
    public static int VerCmp(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.Ordinal))
        {
            return 0;
        }

        int i = 0, j = 0;
        while (i < a.Length || j < b.Length)
        {
            while (i < a.Length && !char.IsAsciiLetterOrDigit(a[i]) && a[i] != '~' && a[i] != '^')
            {
                i++;
            }

            while (j < b.Length && !char.IsAsciiLetterOrDigit(b[j]) && b[j] != '~' && b[j] != '^')
            {
                j++;
            }

            // '~' sorts before everything, including the end of the string.
            if ((i < a.Length && a[i] == '~') || (j < b.Length && b[j] == '~'))
            {
                if (i >= a.Length || a[i] != '~')
                {
                    return 1;
                }

                if (j >= b.Length || b[j] != '~')
                {
                    return -1;
                }

                i++;
                j++;
                continue;
            }

            // '^' sorts after the end of the string but before anything else.
            if ((i < a.Length && a[i] == '^') || (j < b.Length && b[j] == '^'))
            {
                if (i >= a.Length)
                {
                    return -1;
                }

                if (j >= b.Length)
                {
                    return 1;
                }

                if (a[i] != '^')
                {
                    return 1;
                }

                if (b[j] != '^')
                {
                    return -1;
                }

                i++;
                j++;
                continue;
            }

            if (i >= a.Length || j >= b.Length)
            {
                break;
            }

            var startA = i;
            var startB = j;
            var numeric = char.IsAsciiDigit(a[i]);
            if (numeric)
            {
                while (i < a.Length && char.IsAsciiDigit(a[i]))
                {
                    i++;
                }

                while (j < b.Length && char.IsAsciiDigit(b[j]))
                {
                    j++;
                }
            }
            else
            {
                while (i < a.Length && char.IsAsciiLetter(a[i]))
                {
                    i++;
                }

                while (j < b.Length && char.IsAsciiLetter(b[j]))
                {
                    j++;
                }
            }

            var segA = a[startA..i];
            var segB = b[startB..j];
            if (segB.Length == 0)
            {
                // Segments of different types: numeric is newer.
                return numeric ? 1 : -1;
            }

            if (numeric)
            {
                segA = segA.TrimStart('0');
                segB = segB.TrimStart('0');
                if (segA.Length != segB.Length)
                {
                    return segA.Length > segB.Length ? 1 : -1;
                }
            }

            var cmp = string.CompareOrdinal(segA, segB);
            if (cmp != 0)
            {
                return cmp < 0 ? -1 : 1;
            }
        }

        if (i >= a.Length && j >= b.Length)
        {
            return 0;
        }

        return i >= a.Length ? -1 : 1;
    }
}
