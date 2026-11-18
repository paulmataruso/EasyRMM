namespace EasyPatch.Core.Entities;

public enum UserRole
{
    SuperAdmin,
    Admin,
    ReadOnly,
}

public enum EndpointStatus
{
    Active,
    Revoked,
    Decommissioned,
}

/// <summary>Per-endpoint update state. Only scans move an update to <see cref="Installed"/>.</summary>
public enum EndpointUpdateState
{
    Missing,
    Failed,
    PendingVerification,
    PendingReboot,
    Installed,
    Superseded,
    NotApplicable,
    Excluded,

    /// <summary>Windows reported a successful installation (no restart needed), but the next scan still offered the same
    /// revision: a Windows Update detection problem. Not installed again automatically; not counted for compliance.</summary>
    Reoffered,
}

public enum ComplianceStatus
{
    NeverScanned,
    ScanStale,
    FailedUpdates,
    MissingUpdates,
    RebootRequired,
    Compliant,
}

public enum OsSupportStatus
{
    Unknown,
    Supported,
    ExtendedSecurityUpdates,
    Unsupported,
}

public enum EsuOverride
{
    Auto,
    Enrolled,
    NotEnrolled,
}

public enum PolicyScope
{
    Global,
    Organization,
    Site,
    Endpoint,

    /// <summary>Applies to every endpoint with the tag, between the site and endpoint layers.</summary>
    Tag,
}

public enum EnrollmentRequestStatus
{
    Pending,
    Approved,
    Rejected,
    Expired,
}

public enum ScanStatus
{
    Succeeded,
    Failed,
}

public enum EventSeverity
{
    Info,
    Warning,
    Error,
}
