// The certificate authority module's typed results (ADR-0076, section 3).
export interface CaStatus {
  caName: string;
  caType: string;
  enterprise: boolean;
  serviceState: string;
  certificate: { subject: string; thumbprint: string; notAfter: string; daysLeft: number; signatureAlgorithm: string; keyLength: number | null } | null;
  crl: { baseThisUpdate: string | null; baseNextUpdate: string | null; hoursToBaseExpiry: number | null; deltaNextUpdate: string | null } | null;
  counts: { pending: number; issued: number; revoked: number; failed: number } | null;
}
export interface CaTemplate {
  name: string;
  displayName: string;
  schemaVersion: number;
  published: boolean;
  enrolleeSuppliesSubject: boolean;
  authenticationEku: boolean;
  anyPurpose: boolean;
  managerApproval: boolean;
  lowPrivilegeEnroll: boolean;
  risky: boolean;
}
export interface CaTemplates {
  standalone: boolean;
  templates: CaTemplate[];
}
export interface CaFinding {
  id: string;
  class: string;
  subject: string;
  evidence: string;
}
export interface CaFindings {
  caName: string;
  findings: CaFinding[];
  notes: string[];
}
export interface CaRequest {
  id: number;
  requester: string;
  template: string;
  submitted: string | null;
  serial: string;
  notAfter: string | null;
  commonName: string;
  revokedWhen: string | null;
  revokedReason: number | null;
  disposition: string;
}
export interface CaRequests {
  requests: CaRequest[];
  total: number;
  next: number | null;
}
