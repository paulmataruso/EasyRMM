// The print server module's typed results (ADR-0076, section 7).
export interface PrintStatus {
  serviceState: string;
  printerCount: number;
  sharedCount: number;
  jobCount: number;
  domainController: boolean;
}
export interface Printer {
  name: string;
  driver: string;
  port: string;
  shared: boolean;
  shareName: string;
  published: boolean;
  status: string;
  paused: boolean;
  offline: boolean;
  isDefault: boolean;
  jobCount: number;
  jobsInError: number;
  oldestJobAgeMinutes: number | null;
}
export interface PrinterList {
  printers: Printer[];
  truncated: boolean;
}
export interface PrintPort {
  name: string;
  address: string;
  portNumber: number;
  description: string;
}
export interface PrintDriver {
  name: string;
  version: string;
  manufacturer: string;
  environment: string;
  inbox: boolean;
}
export interface PrintJob {
  id: number;
  status: string;
  sizeBytes: number;
  pages: number;
  submitted: string | null;
  ageMinutes: number | null;
}
export interface PrintJobList {
  printer: string;
  jobs: PrintJob[];
  total: number;
}
export interface PrintJobDocs {
  jobs: { id: number; document: string; owner: string; client: string }[];
}
export interface Hardening {
  restrictDriverInstall: number | null;
  noWarningNoElevation: number | null;
  updatePromptSettings: number | null;
  weakened: boolean;
  spoolerRunning: boolean;
  domainController: boolean;
}
