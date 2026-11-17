namespace EasyPatch.Agent.Core.State;

/// <summary>Crash-safe file writes: write to a temporary file, flush to disk, then atomically replace.</summary>
public static class AtomicFile
{
    public static void WriteAllBytes(string path, ReadOnlySpan<byte> data)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        var temp = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }

            ReplaceWithRetry(temp, path);
        }
        finally
        {
            if (File.Exists(temp))
            {
                TryDelete(temp);
            }
        }
    }

    /// <summary>
    /// Reads a file while allowing a concurrent atomic replace (FileShare.Delete), so readers such as
    /// <c>EasyPatch.Agent.exe status</c> never make the service's writes fail.
    /// </summary>
    public static byte[]? TryReadAllBytes(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[stream.Length];
            stream.ReadExactly(buffer);
            return buffer;
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    private static void ReplaceWithRetry(string source, string destination)
    {
        // Antivirus and indexing services briefly open files without delete sharing; retry a few times.
        const int attempts = 6;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Move(source, destination, overwrite: true);
                return;
            }
            catch (Exception ex) when (attempt < attempts && ex is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(25 * attempt * attempt);
            }
        }
    }

    public static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    /// <summary>Removes orphaned temporary files left behind by a crash mid-write.</summary>
    public static void CleanupTemporaryFiles(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(directory, ".*.tmp"))
        {
            TryDelete(file);
        }
    }
}
