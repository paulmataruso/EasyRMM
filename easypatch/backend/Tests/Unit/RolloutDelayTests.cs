using EasyPatch.Contracts;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using Xunit;

namespace EasyPatch.Tests.Unit;

public sealed class RolloutDelayTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    private static EffectivePolicy Policy(int delay, int securityDelay)
    {
        var global = PolicyDefaults.CreateGlobal(Now);
        global.InstallDelayDays = delay;
        global.SecurityInstallDelayDays = securityDelay;
        return PolicyResolver.Resolve(global, null, null);
    }

    private static Update Update(UpdateCategory category, string? classification = null) => new()
    {
        Id = Guid.NewGuid(),
        UpdateGuid = Guid.NewGuid(),
        Title = "Update",
        Category = category,
        MsClassification = classification,
    };

    private static EndpointUpdate Row(Update update, DateTimeOffset detected, DateTimeOffset? basis = null) => new()
    {
        Id = Guid.NewGuid(),
        UpdateGuid = update.UpdateGuid,
        UpdateId = update.Id,
        Update = update,
        State = EndpointUpdateState.Missing,
        FirstDetectedAt = detected,
        LastDetectedAt = detected,
        StateChangedAt = detected,
        DelayBasisAt = basis,
    };

    private static RequirementDecision Evaluate(Update update, EndpointUpdate row, EffectivePolicy policy) =>
        UpdateRequirement.Evaluate(update, row, policy, policy.ToFilter(new HashSet<Guid>()), Now);

    [Fact]
    public void Updates_are_required_immediately_without_a_delay()
    {
        var update = Update(UpdateCategory.Security);
        var decision = Evaluate(update, Row(update, Now), Policy(0, 0));
        Assert.True(decision.Required);
        Assert.Null(decision.DeferredUntil);
    }

    [Fact]
    public void Updates_inside_their_delay_are_deferred_not_required()
    {
        var update = Update(UpdateCategory.Other);
        var decision = Evaluate(update, Row(update, Now.AddDays(-2)), Policy(7, 3));
        Assert.False(decision.Required);
        Assert.False(decision.Excluded);
        Assert.Equal(Now.AddDays(5), decision.DeferredUntil);
    }

    [Fact]
    public void Security_updates_use_the_security_delay()
    {
        var cumulative = Update(UpdateCategory.Cumulative, UpdateRequirement.SecurityClassification);
        Assert.True(UpdateRequirement.IsSecurity(cumulative)); // monthly cumulative updates are classified "Security Updates"
        var decision = Evaluate(cumulative, Row(cumulative, Now.AddDays(-4)), Policy(14, 3));
        Assert.True(decision.Required);
    }

    [Fact]
    public void Definition_updates_are_never_delayed()
    {
        var definition = Update(UpdateCategory.Definition);
        Assert.True(Evaluate(definition, Row(definition, Now), Policy(30, 30)).Required);
    }

    [Fact]
    public void Updates_not_allowed_by_policy_are_neither_required_nor_deferred()
    {
        var driver = Update(UpdateCategory.Driver);
        var decision = Evaluate(driver, Row(driver, Now), Policy(7, 7));
        Assert.False(decision.Required);
        Assert.Null(decision.DeferredUntil);
    }

    [Fact]
    public void Delay_counts_from_the_inherited_basis()
    {
        var update = Update(UpdateCategory.Other);
        var decision = Evaluate(update, Row(update, Now, basis: Now.AddDays(-10)), Policy(7, 7));
        Assert.True(decision.Required);
    }

    [Fact]
    public void Deferred_updates_do_not_count_as_missing_required()
    {
        var a = Update(UpdateCategory.Other);
        var deferred = Row(a, Now);
        deferred.IsRequired = false;
        deferred.DeferredUntil = Now.AddDays(3);
        var b = Update(UpdateCategory.Security);
        var required = Row(b, Now);
        required.IsRequired = true;
        var counts = ComplianceCalculator.Count([deferred, required]);
        Assert.Equal(1, counts.MissingRequired);
        Assert.Equal(1, counts.MissingDeferred);
        Assert.Equal(2, counts.MissingTotal);
    }

    [Fact]
    public void Superseding_update_inherits_the_delay_basis_of_the_update_it_replaces()
    {
        var oldGuid = Guid.NewGuid();
        var oldRow = new EndpointUpdate
        {
            Id = Guid.NewGuid(),
            UpdateGuid = oldGuid,
            State = EndpointUpdateState.Missing,
            FirstDetectedAt = Now.AddDays(-20),
            DelayBasisAt = Now.AddDays(-20),
        };
        var existing = new Dictionary<Guid, EndpointUpdate> { [oldGuid] = oldRow };
        var newGuid = Guid.NewGuid();
        UpdateReconciler.Reconcile(Guid.NewGuid(), existing, [new ReconcileItem(newGuid, Guid.NewGuid(), false, [oldGuid])], [],
            _ => false, (_, _) => true, Guid.NewGuid(), Now);
        Assert.Equal(Now.AddDays(-20), existing[newGuid].DelayBasisAt);
        Assert.Equal(Now, existing[newGuid].FirstDetectedAt);
    }

    [Fact]
    public void Newer_package_version_inherits_the_delay_basis_of_the_same_package_line()
    {
        var oldUpdate = new Update { Id = Guid.NewGuid(), UpdateGuid = Guid.NewGuid(), Title = "openssl", PackageName = "openssl", PackageArchitecture = "amd64" };
        var oldRow = Row(oldUpdate, Now.AddDays(-9), Now.AddDays(-9));
        var existing = new Dictionary<Guid, EndpointUpdate> { [oldUpdate.UpdateGuid] = oldRow };
        var newGuid = Guid.NewGuid();
        UpdateReconciler.Reconcile(Guid.NewGuid(), existing, [new ReconcileItem(newGuid, Guid.NewGuid(), false, [], null, "openssl:amd64")], [],
            _ => false, (_, _) => true, Guid.NewGuid(), Now);
        Assert.Equal(Now.AddDays(-9), existing[newGuid].DelayBasisAt);
        Assert.Equal(EndpointUpdateState.NotApplicable, oldRow.State);
    }

    [Fact]
    public void New_update_uses_when_the_fleet_first_saw_it()
    {
        var existing = new Dictionary<Guid, EndpointUpdate>();
        var guid = Guid.NewGuid();
        UpdateReconciler.Reconcile(Guid.NewGuid(), existing, [new ReconcileItem(guid, Guid.NewGuid(), false, [], Now.AddDays(-3))], [],
            _ => false, (_, _) => true, Guid.NewGuid(), Now);
        Assert.Equal(Now.AddDays(-3), existing[guid].DelayBasisAt);
    }
}

public sealed class TagPolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    private static TagPolicyLayer Tag(string name, int priority, int delay) =>
        new(name, priority, new Policy { Scope = PolicyScope.Tag, InstallDelayDays = delay });

    [Fact]
    public void Tag_layer_overrides_site_and_reports_the_tag()
    {
        var site = new Policy { Scope = PolicyScope.Site, InstallDelayDays = 2 };
        var p = PolicyResolver.Resolve(PolicyDefaults.CreateGlobal(Now), null, site, null, [Tag("pilot", 0, 0)]);
        Assert.Equal(0, p.InstallDelayDays);
        Assert.Equal(PolicyScope.Tag, p.Sources[nameof(EffectivePolicy.InstallDelayDays)]);
        Assert.Equal("pilot", p.SourceTags[nameof(EffectivePolicy.InstallDelayDays)]);
    }

    [Fact]
    public void Higher_priority_tag_wins()
    {
        var p = PolicyResolver.Resolve(PolicyDefaults.CreateGlobal(Now), null, null, null, [Tag("broad", 10, 14), Tag("pilot", 1, 0)]);
        Assert.Equal(14, p.InstallDelayDays);
        Assert.Equal("broad", p.SourceTags[nameof(EffectivePolicy.InstallDelayDays)]);
    }

    [Fact]
    public void Equal_priority_is_decided_by_name()
    {
        var p = PolicyResolver.Resolve(PolicyDefaults.CreateGlobal(Now), null, null, null, [Tag("zeta", 5, 9), Tag("alpha", 5, 4)]);
        Assert.Equal(4, p.InstallDelayDays); // alphabetically first name wins a tie
    }

    [Fact]
    public void Endpoint_policy_overrides_tags()
    {
        var endpoint = new Policy { Scope = PolicyScope.Endpoint, InstallDelayDays = 1 };
        var p = PolicyResolver.Resolve(PolicyDefaults.CreateGlobal(Now), null, null, endpoint, [Tag("ring2", 0, 21)]);
        Assert.Equal(1, p.InstallDelayDays);
        Assert.Equal(PolicyScope.Endpoint, p.Sources[nameof(EffectivePolicy.InstallDelayDays)]);
        Assert.False(p.SourceTags.ContainsKey(nameof(EffectivePolicy.InstallDelayDays)));
    }

    [Fact]
    public void Delay_ranges_are_validated()
    {
        Assert.NotEmpty(PolicyResolver.ValidatePolicy(new Policy { InstallDelayDays = 400 }));
        Assert.NotEmpty(PolicyResolver.ValidatePolicy(new Policy { SecurityInstallDelayDays = 91 }));
        Assert.Empty(PolicyResolver.ValidatePolicy(new Policy { InstallDelayDays = 30, SecurityInstallDelayDays = 7 }));
    }
}
