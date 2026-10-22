import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Input, TagInput, Text } from "@cloudflare/kumo";
import { TrashIcon, PaperPlaneTiltIcon, WrenchIcon, ArrowsClockwiseIcon, BroomIcon, ArrowFatLinesRightIcon, CheckCircleIcon } from "@phosphor-icons/react";
import { PageHeader, Section, ConfirmDialog, Mono } from "../../components/ui";
import { VirtualSelect } from "../../components/VirtualSelect";
import { NameserverList } from "../../components/NameserverInstructions";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys, useCurrentZone, useMe, usePerms } from "../../lib/queries";
import { stripDot } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { SOA, ZoneSettings as ZS } from "../../lib/types";

const soaEditOptions = [
  { value: "DEFAULT", label: "DEFAULT", description: "Date-based serial (YYYYMMDDnn), recommended" },
  { value: "INCREASE", label: "INCREASE", description: "Increment the serial by one on each change" },
  { value: "EPOCH", label: "EPOCH", description: "Serial is the current Unix timestamp" },
  { value: "INCEPTION-INCREMENT", label: "INCEPTION-INCREMENT", description: "Recommended for DNSSEC-signed zones" },
  { value: "OFF", label: "OFF", description: "Never change the serial automatically" },
];

function NumberField({ label, value, onChange, error, description }: { label: string; value: number; onChange: (n: number) => void; error?: string; description?: string }) {
  return <Input label={label} type="number" value={String(value)} onChange={(e) => onChange(Number(e.target.value))} error={error} description={description} />;
}

export default function ZoneSettings() {
  const { zone, orgId } = useCurrentZone();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const me = useMe();
  const { can, role } = usePerms(orgId);
  const settings = useQuery({
    queryKey: keys.zoneSettings(orgId, zone?.id ?? ""),
    queryFn: () => api<ZS>(`/orgs/${orgId}/zones/${zone!.id}/settings`),
    enabled: !!zone,
  });
  const [soa, setSoa] = useState<SOA | null>(null);
  const [soaEdit, setSoaEdit] = useState("DEFAULT");
  const [kind, setKind] = useState("Native");
  const [catalog, setCatalog] = useState("");
  const [masters, setMasters] = useState<string[]>([]);
  const [axfrFrom, setAxfrFrom] = useState<string[]>([]);
  const [alsoNotify, setAlsoNotify] = useState<string[]>([]);
  const [tsigAllow, setTsigAllow] = useState<string[]>([]);
  const [masterTsig, setMasterTsig] = useState<string[]>([]);
  const [nsSet, setNsSet] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [moveTarget, setMoveTarget] = useState("");

  useEffect(() => {
    const s = settings.data;
    if (!s) return;
    setSoa(s.soa);
    setSoaEdit(s.soa_edit_api || "DEFAULT");
    setKind(s.kind);
    setCatalog(s.catalog ?? "");
    setMasters(s.masters);
    setAxfrFrom(s.allow_axfr_from);
    setAlsoNotify(s.also_notify);
    setTsigAllow(s.tsig_allow_axfr);
    setMasterTsig(s.axfr_master_tsig);
    setNsSet(s.nameserver_set_id ?? "");
  }, [settings.data]);

  const onSaved = (d: ZS, msg: string) => {
    qc.setQueryData(keys.zoneSettings(orgId, zone!.id), d);
    void qc.invalidateQueries({ queryKey: keys.zones(orgId) });
    toast.success(msg);
  };
  const patch = (body: Record<string, unknown>) => api<ZS>(`/orgs/${orgId}/zones/${zone!.id}/settings`, { method: "PATCH", body });
  const saveSoa = useMutation({ mutationFn: () => patch({ soa, soa_edit_api: soaEdit }), onSuccess: (d) => onSaved(d, "SOA updated") });
  const saveTransfer = useMutation({
    mutationFn: () => patch({ kind, catalog, masters, allow_axfr_from: axfrFrom, also_notify: alsoNotify, tsig_allow_axfr: tsigAllow, axfr_master_tsig: masterTsig }),
    onSuccess: (d) => onSaved(d, "Transfer settings updated"),
  });
  const changeNs = useMutation({
    mutationFn: () => api(`/orgs/${orgId}/zones/${zone!.id}/nameservers`, { method: "POST", body: { nameserver_set_id: nsSet } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.zones(orgId) });
      void settings.refetch();
      toast.success("Nameservers changed", "Update the delegation at your registrar to match.");
    },
    onError: (e) => toast.error(e),
  });
  const action = useMutation({
    mutationFn: (a: string) => api(`/orgs/${orgId}/zones/${zone!.id}/${a}`, { method: "POST" }),
    onSuccess: (_, a) => {
      void qc.invalidateQueries({ queryKey: keys.zones(orgId) });
      const labels: Record<string, string> = {
        "actions/notify": "NOTIFY sent to secondaries",
        "actions/rectify": "Zone rectified",
        "actions/axfr-retrieve": "Zone transfer requested",
        "actions/flush-cache": "Cache flushed",
        "check-nameservers": "Delegation checked",
        activate: "Zone activated",
      };
      toast.success(labels[a] ?? "Done");
    },
    onError: (e) => toast.error(e),
  });
  const del = useMutation({
    mutationFn: () => api(`/orgs/${orgId}/zones/${zone!.id}`, { method: "DELETE", body: { confirm: stripDot(zone!.name) } }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: keys.zones(orgId) });
      void qc.invalidateQueries({ queryKey: keys.org(orgId) });
      toast.success("Domain deleted");
      navigate(`/${orgId}`, { replace: true });
    },
    onError: (e) => toast.error(e, "Could not delete domain"),
  });
  const move = useMutation({
    mutationFn: () => api<{ org_id: string }>(`/orgs/${orgId}/zones/${zone!.id}/move`, { method: "POST", body: { target_org_id: moveTarget } }),
    onSuccess: async (d) => {
      await qc.invalidateQueries();
      toast.success("Domain moved");
      navigate(`/${d.org_id}/${stripDot(zone!.name)}`);
    },
    onError: (e) => toast.error(e, "Could not move domain"),
  });

  if (!zone) return null;
  const editable = can("zones.edit");
  const s = settings.data;
  const isAdmin = role === "owner" || role === "admin";
  const moveTargets = (me.data?.orgs ?? []).filter((o) => o.id !== orgId && (o.role === "owner" || o.role === "admin" || me.data?.user.is_superadmin));

  return (
    <div className="grid max-w-4xl gap-6">
      <PageHeader title="Zone settings" description={`Configuration for ${stripDot(zone.name)}.`} />
      {settings.error && <Banner variant="error" description={errorMessage(settings.error)} />}

      <Section
        title="Nameservers"
        description="The authoritative nameservers assigned to this zone. Changing the set updates apex NS records and requires a registrar update."
        footer={
          editable &&
          s &&
          s.nameserver_sets.length > 1 && (
            <Button variant="primary" loading={changeNs.isPending} disabled={!nsSet || nsSet === s.nameserver_set_id} onClick={() => changeNs.mutate()}>
              Change nameservers
            </Button>
          )
        }
      >
        <div className="grid gap-4">
          <NameserverList nameservers={zone.assigned_nameservers} />
          {editable && s && s.nameserver_sets.length > 1 && (
            <VirtualSelect
              label="Nameserver set"
              options={s.nameserver_sets.map((x) => ({ value: x.id, label: x.name, description: x.nameservers.map(stripDot).join(", ") }))}
              value={nsSet}
              onChange={setNsSet}
            />
          )}
        </div>
      </Section>

      {soa && zone.kind !== "Slave" && (
        <Section
          title="Start of authority (SOA)"
          description="Controls how secondaries refresh the zone and how long negative answers are cached."
          footer={
            editable && (
              <Button variant="primary" loading={saveSoa.isPending} onClick={() => saveSoa.mutate()}>
                Save SOA
              </Button>
            )
          }
        >
          <fieldset disabled={!editable} className="grid gap-4">
            {saveSoa.error && Object.keys((saveSoa.error as { fields?: object }).fields ?? {}).length === 0 && (
              <Banner variant="error" size="sm" description={errorMessage(saveSoa.error)} />
            )}
            <div className="grid gap-4 md:grid-cols-2">
              <Input label="Primary nameserver (MNAME)" value={soa.primary} onChange={(e) => setSoa({ ...soa, primary: e.target.value })} error={fieldError(saveSoa.error, "soa.primary")} />
              <Input label="Hostmaster email (RNAME)" value={soa.hostmaster} onChange={(e) => setSoa({ ...soa, hostmaster: e.target.value })} error={fieldError(saveSoa.error, "soa.hostmaster")} />
            </div>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
              <NumberField label="Refresh" value={soa.refresh} onChange={(n) => setSoa({ ...soa, refresh: n })} error={fieldError(saveSoa.error, "soa.refresh")} />
              <NumberField label="Retry" value={soa.retry} onChange={(n) => setSoa({ ...soa, retry: n })} error={fieldError(saveSoa.error, "soa.retry")} />
              <NumberField label="Expire" value={soa.expire} onChange={(n) => setSoa({ ...soa, expire: n })} error={fieldError(saveSoa.error, "soa.expire")} />
              <NumberField label="Negative TTL" value={soa.minimum} onChange={(n) => setSoa({ ...soa, minimum: n })} error={fieldError(saveSoa.error, "soa.minimum")} />
              <NumberField label="SOA TTL" value={soa.ttl} onChange={(n) => setSoa({ ...soa, ttl: n })} error={fieldError(saveSoa.error, "soa.ttl")} />
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <VirtualSelect label="Serial policy (SOA-EDIT-API)" options={soaEditOptions} value={soaEdit} onChange={setSoaEdit} disabled={!editable} />
              <div className="grid content-start gap-1.5">
                <Text bold>Current serial</Text>
                <Mono className="text-base">{s?.serial}</Mono>
              </div>
            </div>
          </fieldset>
        </Section>
      )}

      <Section
        title="Zone type and transfers"
        description="Replication with external secondaries or primaries over AXFR and NOTIFY."
        footer={
          editable && (
            <Button variant="primary" loading={saveTransfer.isPending} onClick={() => saveTransfer.mutate()}>
              Save transfer settings
            </Button>
          )
        }
      >
        <div className="grid gap-4">
          {saveTransfer.error && <Banner variant="error" size="sm" description={errorMessage(saveTransfer.error)} />}
          <VirtualSelect
            label="Zone type"
            disabled={!editable}
            options={[
              { value: "Native", label: "Native", description: "Replicated by the database backend" },
              { value: "Master", label: "Primary", description: "Sends NOTIFY and serves AXFR to secondaries" },
              { value: "Slave", label: "Secondary", description: "Transfers from primary servers" },
              { value: "Producer", label: "Catalog producer", description: "Publishes a catalog of member zones" },
              { value: "Consumer", label: "Catalog consumer", description: "Provisions zones from a remote catalog" },
            ]}
            value={kind}
            onChange={setKind}
          />
          <Input
            label="Catalog zone"
            required={false}
            placeholder="catalog.example.net"
            description="Add this zone as a member of a catalog zone so secondaries provision it automatically."
            value={catalog}
            onChange={(e) => setCatalog(e.target.value)}
            disabled={!editable || kind === "Producer" || kind === "Consumer"}
            error={fieldError(saveTransfer.error, "catalog")}
          />
          {(kind === "Slave" || kind === "Consumer") && (
            <TagInput label="Primary servers" placeholder="192.0.2.53:53" value={masters} onValueChange={(v: string[]) => setMasters(v)} error={fieldError(saveTransfer.error, "masters")} disabled={!editable} />
          )}
          <TagInput
            label="Allow AXFR from"
            description="IP addresses or CIDR ranges allowed to transfer this zone. Use AUTO-NS to allow the zone's own nameservers."
            placeholder="198.51.100.0/24"
            value={axfrFrom}
            onValueChange={(v: string[]) => setAxfrFrom(v)}
            error={fieldError(saveTransfer.error, "allow_axfr_from")}
            disabled={!editable}
          />
          <TagInput
            label="Also notify"
            description="Additional secondaries to NOTIFY on change."
            placeholder="198.51.100.53"
            value={alsoNotify}
            onValueChange={(v: string[]) => setAlsoNotify(v)}
            error={fieldError(saveTransfer.error, "also_notify")}
            disabled={!editable}
          />
          <div className="grid gap-4 md:grid-cols-2">
            <TagInput label="TSIG keys allowed to AXFR" placeholder="transfer-key" value={tsigAllow} onValueChange={(v: string[]) => setTsigAllow(v)} disabled={!editable} />
            <TagInput label="TSIG key for inbound AXFR" placeholder="primary-key" value={masterTsig} onValueChange={(v: string[]) => setMasterTsig(v)} disabled={!editable} />
          </div>
        </div>
      </Section>

      {editable && (
        <Section title="Operations">
          <div className="flex flex-wrap gap-2">
            <Button icon={<ArrowsClockwiseIcon />} loading={action.isPending && action.variables === "check-nameservers"} onClick={() => action.mutate("check-nameservers")}>
              Check delegation
            </Button>
            {zone.kind !== "Native" && zone.kind !== "Slave" && (
              <Button icon={<PaperPlaneTiltIcon />} onClick={() => action.mutate("actions/notify")}>
                Send NOTIFY
              </Button>
            )}
            {zone.kind === "Slave" && (
              <Button icon={<ArrowsClockwiseIcon />} onClick={() => action.mutate("actions/axfr-retrieve")}>
                Retrieve from primary
              </Button>
            )}
            <Button icon={<WrenchIcon />} onClick={() => action.mutate("actions/rectify")}>
              Rectify zone
            </Button>
            <Button icon={<BroomIcon />} onClick={() => action.mutate("actions/flush-cache")}>
              Flush server cache
            </Button>
            {zone.status !== "active" && isAdmin && (
              <Button icon={<CheckCircleIcon />} onClick={() => action.mutate("activate")}>
                Activate without verification
              </Button>
            )}
          </div>
        </Section>
      )}

      {can("zones.delete") && moveTargets.length > 0 && (
        <Section
          title="Move to another organization"
          description="Transfers the zone and its records. Members of this organization lose access."
          footer={
            <Button icon={<ArrowFatLinesRightIcon />} loading={move.isPending} disabled={!moveTarget} onClick={() => move.mutate()}>
              Move domain
            </Button>
          }
        >
          <VirtualSelect
            label="Destination organization"
            options={moveTargets.map((o) => ({ value: o.id, label: o.name }))}
            value={moveTarget}
            onChange={setMoveTarget}
            placeholder="Choose an organization"
          />
        </Section>
      )}

      {can("zones.delete") && (
        <Section danger title="Delete domain" description="Removes the zone and all of its records from the DNS server. Queries will fail immediately.">
          <Button variant="destructive" icon={<TrashIcon />} onClick={() => setDeleting(true)}>
            Delete {stripDot(zone.name)}
          </Button>
        </Section>
      )}
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title="Delete domain"
        description="This removes every record and DNSSEC key. It cannot be undone."
        confirmText={stripDot(zone.name)}
        confirmLabel="Delete domain"
        loading={del.isPending}
        onConfirm={() => del.mutate()}
      />
    </div>
  );
}
