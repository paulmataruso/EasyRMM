// The file-sharing module's typed results (ADR-0076, section 6).
export interface SharesStatus {
  serviceState: string;
  shareCount: number;
  userShareCount: number;
  sessionCount: number;
  openFileCount: number;
  smb1Enabled: boolean | null;
  signingRequired: boolean | null;
  encryptionRequired: boolean | null;
}
export interface Share {
  name: string;
  path: string;
  description: string;
  special: boolean;
  protected: boolean;
  scoped: boolean;
  continuouslyAvailable: boolean;
  encrypted: boolean;
  caching: string;
  folderEnumeration: string;
  concurrentUserLimit: number;
}
export interface ShareList {
  shares: Share[];
  truncated: boolean;
}
export interface ShareAccess {
  name: string;
  entries: { account: string; right: string; type: string }[];
}
export interface SmbSession {
  id: string;
  user: string;
  client: string;
  openFiles: number;
  secondsActive: number;
  secondsIdle: number;
}
export interface SessionList {
  sessions: SmbSession[];
  total: number;
}
export interface OpenFile {
  id: string;
  sessionId: string;
  path: string;
  user: string;
  client: string;
  locks: number;
}
export interface OpenFileList {
  files: OpenFile[];
  total: number;
}
