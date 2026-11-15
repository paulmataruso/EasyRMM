import type { ReactNode } from "react";
import { Link } from "react-router";
import { ApiError } from "../../api/client";
import { useApi } from "../../api/hooks";
import type { RemoteAccessStatus } from "../../api/types";
import { Alert, Badge, Card, Dot, EmptyState, ErrorState, KeyValueList, Mono, Spinner } from "../../components/ui";
import { formatDateTime, formatNumber, formatRelative } from "../../lib/format";

export function RemoteAccessTab() {
  const status = useApi<RemoteAccessStatus>("/remote-access/status", undefined, { refetchInterval: 15_000 });

  if (status.isPending) return <Spinner />;
  if (status.error instanceof ApiError && status.error.status === 404) {
    return (
      <EmptyState title="Remote access is turned off">
        This server was started with <Mono>EASYRMM_MESH_ENABLED=false</Mono>, so there are no remote sessions and no device discovery.
      </EmptyState>
    );
  }
  if (status.isError) return <ErrorState error={status.error} onRetry={() => void status.refetch()} />;
  const s = status.data;

  return (
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
      <Card title="MeshCentral" className="xl:col-span-2">
        {!s.connected && (
          <Alert tone="warn" className="mb-4" title="EasyRMM cannot reach MeshCentral">
            Device status is not being updated and remote sessions cannot start. Check the meshcentral service with{" "}
            <Mono>docker compose ps</Mono> and <Mono>docker compose logs meshcentral</Mono>. EasyRMM reconnects on its own.
          </Alert>
        )}
        <KeyValueList
          items={[
            [
              "Connection",
              s.connected ? (
                <Badge tone="ok" icon={<Dot tone="ok" />}>
                  Connected
                </Badge>
              ) : (
                <Badge tone="warn" icon={<Dot tone="warn" />}>
                  Unavailable
                </Badge>
              ),
            ],
            ["Address", s.address ? <Mono>{s.address}</Mono> : "—"],
            [
              "Last synchronized",
              s.lastSyncAt ? <span title={formatDateTime(s.lastSyncAt)}>{formatRelative(s.lastSyncAt)}</span> : <span className="text-muted">Not yet</span>,
            ],
            ...(s.lastError
              ? ([
                  [
                    "Last error",
                    <span key="e">
                      <span className="block break-words text-danger">{s.lastError}</span>
                      {s.lastErrorAt && (
                        <span className="text-xs text-muted" title={formatDateTime(s.lastErrorAt)}>
                          {formatRelative(s.lastErrorAt)}
                        </span>
                      )}
                    </span>,
                  ],
                ] as [string, ReactNode][])
              : []),
            [
              "Devices",
              <Link key="d" to="/devices" className="text-accent hover:underline">
                {formatNumber(s.devices)} known, {formatNumber(s.devicesOnline)} online
              </Link>,
            ],
          ]}
        />
      </Card>
      <Card title="How it works">
        <div className="space-y-2 text-sm text-muted">
          <p>
            EasyRMM keeps MeshCentral in step with this console: each site has a device group there, and each person with remote-session rights has an
            account limited to the sites their roles cover.
          </p>
          <p>Changes to organizations, sites, users and roles apply within seconds. A full check also runs every five minutes.</p>
          <p>Sessions are opened from a device's page. Each one is authorized here, recorded in the audit log, and ends when the console session does.</p>
        </div>
      </Card>
    </div>
  );
}
