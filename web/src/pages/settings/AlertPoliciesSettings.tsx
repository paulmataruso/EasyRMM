import { PolicyTable } from "../alerts/PolicyTable";

/** Settings → Alert policies: the shared policies, which cover every device in every organization (ADR-0072). */
export function AlertPoliciesSettings() {
  return <PolicyTable scope={{ level: "shared" }} />;
}
