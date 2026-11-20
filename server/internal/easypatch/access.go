package easypatch

// The patching engine's roles. Each statement names the one a call needs
// (ADR-0038): ReadOnly to read, Admin to change an organization's patching,
// SuperAdmin for what spans the whole engine. EasyRMM decides first, from
// its own permissions; the engine checks the role and organizations again.
const (
	RoleSuperAdmin = "SuperAdmin"
	RoleAdmin      = "Admin"
	RoleReadOnly   = "ReadOnly"
)
