export interface User {
  id: string;
  email: string;
  username: string;
  display_name: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login_at?: string;
  created_at: string;
  updated_at: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Site {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Device {
  id: string;
  organization_id: string;
  site_id: string;
  device_group_id?: string;
  hostname: string;
  display_name?: string;
  os_type: 'windows' | 'linux';
  os_name?: string;
  os_version?: string;
  os_build?: string;
  arch?: string;
  mesh_node_id?: string;
  cpu_model?: string;
  cpu_cores?: number;
  total_memory_mb?: number;
  serial_number?: string;
  manufacturer?: string;
  model?: string;
  agent_id: string;
  agent_version?: string;
  status: 'pending' | 'online' | 'offline' | 'alert';
  last_seen_at?: string;
  enrolled_at?: string;
  tags: string[];
  custom_properties: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DeviceListResponse {
  devices: Device[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface DeviceStats {
  online: number;
  offline: number;
  alert: number;
  pending: number;
}

export interface Alert {
  id: string;
  device_id: string;
  organization_id: string;
  severity: 'info' | 'warning' | 'critical';
  message: string;
  metric: string;
  status: 'active' | 'acknowledged' | 'resolved';
  created_at: string;
}

export interface Job {
  id: string;
  organization_id: string;
  name: string;
  job_type: string;
  status: string;
  target_type: string;
  target_id: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  user_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  ip_address?: string;
  created_at: string;
}
