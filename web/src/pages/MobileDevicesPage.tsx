import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import { RefreshCw, Smartphone, X } from "lucide-react";
import { Badge } from "@nous-research/ui/ui/components/badge";
import { Button } from "@nous-research/ui/ui/components/button";
import { Card, CardContent } from "@nous-research/ui/ui/components/card";
import { H2 } from "@nous-research/ui/ui/components/typography/h2";
import { Spinner } from "@nous-research/ui/ui/components/spinner";
import { Toast } from "@nous-research/ui/ui/components/toast";
import { useToast } from "@nous-research/ui/hooks/use-toast";
import { api, type MobileDeviceRecord } from "@/lib/api";
import { usePageHeader } from "@/contexts/usePageHeader";

function statusTone(status: string): "success" | "warning" | "outline" {
  if (status === "approved") return "success";
  if (status === "pending") return "warning";
  return "outline";
}

export default function MobileDevicesPage() {
  const [devices, setDevices] = useState<MobileDeviceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);
  const { toast, showToast } = useToast();
  const { setEnd } = usePageHeader();

  const load = useCallback(() => {
    setLoading(true);
    api
      .getMobileDevices()
      .then((response) => setDevices(response.devices))
      .catch(() => showToast("Failed to load Hermes Mobile devices", "error"))
      .finally(() => setLoading(false));
  }, [showToast]);

  useEffect(() => {
    load();
  }, [load]);

  useLayoutEffect(() => {
    setEnd(
      <Button
        size="sm"
        className="uppercase"
        onClick={load}
        disabled={loading}
        prefix={loading ? <Spinner /> : <RefreshCw className="h-4 w-4" />}
      >
        Refresh
      </Button>,
    );
    return () => setEnd(null);
  }, [load, loading, setEnd]);

  const revoke = async (device: MobileDeviceRecord) => {
    if (device.status === "revoked") return;
    if (!window.confirm(`Revoke "${device.device_label || device.device_id}" immediately?`)) return;
    setRevoking(device.device_id);
    try {
      const result = await api.revokeMobileDevice(device.device_id);
      showToast(
        result.relay_reconciled === false
          ? "Device revoked locally; relay reconciliation is pending."
          : "Device revoked immediately.",
        "success",
      );
      load();
    } catch (error) {
      showToast(`Device revocation failed: ${error}`, "error");
    } finally {
      setRevoking(null);
    }
  };

  if (loading && devices.length === 0) {
    return (
      <div className="flex items-center justify-center py-24">
        <Spinner className="text-2xl text-primary" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <Toast toast={toast} />
      <div className="flex flex-col gap-2">
        <H2 variant="sm" className="flex items-center gap-2 text-muted-foreground">
          <Smartphone className="h-4 w-4" />
          Hermes Mobile devices ({devices.length})
        </H2>
        <p className="text-sm text-muted-foreground">
          Host-approved phones are scoped to the profiles and capabilities shown below. Revocation
          invalidates the device session and active mobile streams immediately.
        </p>
      </div>

      {devices.length === 0 && (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            No Hermes Mobile devices are enrolled.
          </CardContent>
        </Card>
      )}

      {devices.map((device) => (
        <Card key={device.device_id}>
          <CardContent className="flex items-start gap-4 py-4">
            <div className="flex-1 min-w-0">
              <div className="mb-1 flex items-center gap-2">
                <Badge tone={statusTone(device.status)}>{device.status}</Badge>
                <span className="truncate text-sm font-medium">
                  {device.device_label || "Unnamed device"}
                </span>
              </div>
              <div className="mb-2 truncate font-mono text-xs text-muted-foreground">
                {device.device_id}
              </div>
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                <span>Profiles: {device.profiles.join(", ") || "none"}</span>
                <span>Scopes: {device.scopes.join(", ") || "none"}</span>
              </div>
            </div>
            <Button
              ghost
              size="icon"
              title="Revoke device"
              aria-label={`Revoke ${device.device_label || device.device_id}`}
              className="shrink-0 text-destructive"
              onClick={() => void revoke(device)}
              disabled={device.status === "revoked" || revoking === device.device_id}
            >
              {revoking === device.device_id ? <Spinner /> : <X />}
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
