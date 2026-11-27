// The asset record (ADR-0066, slice 2).

export type AssetSource = "agent" | "manual";

export interface AssetSourceValue {
  source: AssetSource;
  value: string;
  state: "reported" | "unknown" | "unsupported" | "unavailable";
  reason?: string;
  observedAt?: string;
  recordedAt: string;
}

/** A field with each source's value and the one that decides. */
export interface AssetField {
  field: string;
  label: string;
  effective: string;
  sources: AssetSourceValue[];
  /** A person's value and the agent's reported one are both set and unequal. */
  differs: boolean;
  editable: boolean;
}

export interface Asset {
  id: string;
  organizationId: string;
  siteId: string;
  siteName: string;
  deviceId: string | null;
  deviceName?: string;
  kind: string;
  status: string;
  name: string;
  manufacturer: string;
  model: string;
  serialNumber: string;
  sku: string;
  chassisType: string;
  assetTag: string;
  smbiosUuid: string;
  purchaseDate: string | null;
  warrantyExpiry: string | null;
  warrantyStatus: string;
  osEolDate: string | null;
  notes: string;
  warrantyState: "" | "active" | "expiring" | "expired";
  ageStatus: "" | "ok" | "aging" | "end_of_life";
  osSupport: "" | "supported" | "ending" | "ended";
  fields?: AssetField[];
  canManage: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface AssetPage {
  items: Asset[];
  total: number;
}

export interface AssetPatch {
  kind?: string;
  status?: string;
  notes?: string;
  /** A field set to null removes its manual value. */
  fields?: Record<string, string | null>;
  confirmDuplicateSerial?: boolean;
}

export interface AssetAgePolicy {
  agingMonths: number;
  eolMonths: number;
}
