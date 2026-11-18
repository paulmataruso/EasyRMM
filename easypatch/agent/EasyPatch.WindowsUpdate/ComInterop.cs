using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;

namespace EasyPatch.WindowsUpdate;

/// <summary>
/// Minimal late-bound IDispatch helper for the Windows Update Agent automation objects. Uses
/// <see cref="Type.InvokeMember(string, BindingFlags, Binder, object, object[])"/> (IDispatch::GetIDsOfNames +
/// Invoke), which is the documented, stable surface of the WUA scripting API and requires no interop assembly.
/// </summary>
internal static class Com
{
    public static object Create(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: false)
            ?? throw new COMException($"COM class '{progId}' is not registered (Windows Update Agent unavailable).", unchecked((int)0x80040154));
        return Activator.CreateInstance(type) ?? throw new COMException($"Could not create '{progId}'.");
    }

    public static object? Get(object target, string property, params object[] args) =>
        Call(target, property, BindingFlags.GetProperty, args);

    public static void Set(object target, string property, object? value) =>
        Call(target, property, BindingFlags.SetProperty, [value!]);

    public static object? Invoke(object target, string method, params object[] args) =>
        Call(target, method, BindingFlags.InvokeMethod, args);

    /// <summary>Sets a property and ignores failures (used for optional interfaces such as IUpdateSession2/IUpdateInstaller2).</summary>
    public static bool TrySet(object target, string property, object? value)
    {
        try
        {
            Set(target, property, value);
            return true;
        }
        catch (COMException)
        {
            return false;
        }
        catch (MissingMemberException)
        {
            return false;
        }
    }

    public static string? GetString(object target, string property) =>
        Get(target, property) is { } value ? Convert.ToString(value, CultureInfo.InvariantCulture) : null;

    public static bool GetBool(object target, string property, bool fallback = false)
    {
        try
        {
            return Get(target, property) is { } value ? Convert.ToBoolean(value, CultureInfo.InvariantCulture) : fallback;
        }
        catch (COMException)
        {
            return fallback;
        }
    }

    public static int GetInt(object target, string property, int fallback = 0)
    {
        try
        {
            return Get(target, property) is { } value ? Convert.ToInt32(value, CultureInfo.InvariantCulture) : fallback;
        }
        catch (COMException)
        {
            return fallback;
        }
    }

    public static int? TryGetInt(object target, string property)
    {
        try
        {
            return Get(target, property) is { } value ? Convert.ToInt32(value, CultureInfo.InvariantCulture) : null;
        }
        catch (COMException)
        {
            return null;
        }
    }

    public static long? TryGetLong(object target, string property)
    {
        try
        {
            // WUA exposes sizes as DECIMAL.
            return Get(target, property) is { } value ? Convert.ToInt64(value, CultureInfo.InvariantCulture) : null;
        }
        catch (COMException)
        {
            return null;
        }
        catch (OverflowException)
        {
            return null;
        }
    }

    public static DateTimeOffset? TryGetDate(object target, string property)
    {
        try
        {
            if (Get(target, property) is DateTime value && value.Year > 1900)
            {
                // WUA dates are UTC.
                return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc));
            }
        }
        catch (COMException)
        {
        }

        return null;
    }

    /// <summary>Enumerates a WUA collection (Count + Item(index)), releasing nothing (caller owns items).</summary>
    public static IEnumerable<object> Items(object? collection)
    {
        if (collection is null)
        {
            yield break;
        }

        var count = GetInt(collection, "Count");
        for (var i = 0; i < count; i++)
        {
            if (Get(collection, "Item", i) is { } item)
            {
                yield return item;
            }
        }
    }

    /// <summary>Reads a WUA IStringCollection into a list.</summary>
    public static List<string> Strings(object? collection)
    {
        var result = new List<string>();
        foreach (var item in Items(collection))
        {
            if (Convert.ToString(item, CultureInfo.InvariantCulture) is { Length: > 0 } text)
            {
                result.Add(text);
            }
        }

        return result;
    }

    public static void Release(object? comObject)
    {
        if (comObject is not null && Marshal.IsComObject(comObject))
        {
            Marshal.FinalReleaseComObject(comObject);
        }
    }

    private static object? Call(object target, string name, BindingFlags flags, object[] args)
    {
        ArgumentNullException.ThrowIfNull(target);
        try
        {
            return target.GetType().InvokeMember(name, flags, binder: null, target, args, CultureInfo.InvariantCulture);
        }
        catch (TargetInvocationException ex) when (ex.InnerException is not null)
        {
            ExceptionDispatchInfoThrow(ex.InnerException);
            throw; // unreachable
        }
    }

    private static void ExceptionDispatchInfoThrow(Exception inner) =>
        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(inner).Throw();
}

/// <summary>
/// Runs COM work on a dedicated MTA thread so long WUA calls never block thread-pool threads. Synchronous WUA calls
/// cannot be interrupted; when the cancellation token fires (service stop) the caller stops waiting and
/// the background thread finishes or dies with the process. Jobs are resumed idempotently on the next start.
/// </summary>
internal static class ComThread
{
    public static Task<T> RunAsync<T>(Func<T> work, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var completion = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                completion.SetResult(work());
            }
            catch (Exception ex)
            {
                completion.SetException(ex);
            }
        })
        {
            IsBackground = true,
            Name = "EasyPatch WUA",
        };
        thread.SetApartmentState(ApartmentState.MTA);
        thread.Start();
        return completion.Task.WaitAsync(cancellationToken);
    }
}
