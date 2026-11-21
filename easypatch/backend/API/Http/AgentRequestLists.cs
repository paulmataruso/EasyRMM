using System.Collections;
using System.Text.Json.Serialization.Metadata;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;

namespace EasyPatch.Api;

/// <summary>
/// Refuses an agent request that sends <c>null</c> for a list anywhere in its body (<c>"activeJobIds": null</c> in a check-in,
/// <c>"kbNumbers": null</c> in one of a scan's updates): 400 <see cref="AgentErrorCodes.ValidationFailed"/> naming the lists in
/// <c>errors</c>, where the engine would otherwise fail with 500. A list left out still reads as empty. EasyPatch agents never send
/// null: every version writes its requests with <see cref="ContractJson.Options"/>, which leaves out a member that is null.
/// </summary>
internal static class AgentRequestLists
{
    private const string Message = "Must be a list (empty when there is nothing to report), not null.";

    /// <summary>The most lists one refusal names.</summary>
    private const int MaxNamed = 20;

    /// <summary>Endpoint filter for the agent routes: checks the request body, the argument whose type is an agent contract.</summary>
    public static ValueTask<object?> RefuseNullLists(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);
        foreach (var argument in context.Arguments)
        {
            if (argument is not null && argument.GetType().Assembly == typeof(CheckInRequest).Assembly &&
                ContractJson.Options.GetTypeInfo(argument.GetType()) is { Kind: JsonTypeInfoKind.Object } body)
            {
                var errors = new Validator();
                var named = 0;
                Walk(argument, body, string.Empty, errors, ref named);
                errors.ThrowIfInvalid();
            }
        }

        return next(context);
    }

    /// <summary>Every list member of <paramref name="value"/> and of the objects it holds, found from the JSON contract (so the
    /// names are the JSON names, and a list added to a request later is checked too).</summary>
    private static void Walk(object value, JsonTypeInfo type, string path, Validator errors, ref int named)
    {
        foreach (var property in type.Properties)
        {
            if (named >= MaxNamed)
            {
                return;
            }

            var member = ContractJson.Options.GetTypeInfo(property.PropertyType);
            if (property.Get is null || member.Kind is not (JsonTypeInfoKind.Enumerable or JsonTypeInfoKind.Object))
            {
                continue;
            }

            var child = property.Get(value);
            if (member.Kind == JsonTypeInfoKind.Object)
            {
                if (child is not null)
                {
                    Walk(child, member, path + property.Name + ".", errors, ref named);
                }
            }
            else if (child is null)
            {
                errors.Add(path + property.Name, Message);
                named++;
            }
            else if (ContractJson.Options.GetTypeInfo(member.ElementType!) is { Kind: JsonTypeInfoKind.Object } element)
            {
                var index = 0;
                foreach (var item in (IEnumerable)child)
                {
                    if (item is not null)
                    {
                        Walk(item, element, $"{path}{property.Name}[{index}].", errors, ref named);
                    }

                    index++;
                }
            }
        }
    }
}
