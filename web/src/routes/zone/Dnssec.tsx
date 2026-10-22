import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, ClipboardText, Dialog, Switch, Text } from "@cloudflare/kumo";
import { LockKeyIcon, LockKeyOpenIcon, PlusIcon, XIcon, InfoIcon } from "@phosphor-icons/react";
import { PageHeader, Section, ConfirmDialog, DetailRow, Mono } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { api, errorMessage } from "../../lib/api";
import { keys, useCurrentZone, usePerms } from "../../lib/queries";
import { dnssecAlgorithms, parseDS } from "../../lib/dns";
import { stripDot } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { CryptoKey, DnssecInfo } from "../../lib/types";

const digestNames: Record<string, string> = { "1": "SHA-1", "2": "SHA-256", "4": "SHA-384" };

export default function Dnssec() {
  const { zone, orgId } = useCurrentZone();
  const qc = useQueryClient();
  const { can } = usePerms(orgId);
  const info = useQuery({
    queryKey: keys.dnssec(orgId, zone?.id ?? ""),
    queryFn: () => api<DnssecInfo>(`/orgs/${orgId}/zones/${zone!.id}/dnssec`),
    enabled: !!zone,
  });
  const [enableOpen, setEnableOpen] = useState(false);
  const [algorithm, setAlgorithm] = useState("ecdsap256sha256");
  const [nsec3, setNsec3] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [keytype, setKeytype] = useState("zsk");
  const [deletingKey, setDeletingKey] = useState<CryptoKey | null>(null);

  const set = (d: DnssecInfo) => {
    qc.setQueryData(keys.dnssec(orgId, zone!.id), d);
    void qc.invalidateQueries({ queryKey: keys.zoneOverview(orgId, zone!.id) });
  };
  const enable = useMutation({
    mutationFn: () => api<DnssecInfo>(`/orgs/${orgId}/zones/${zone!.id}/dnssec/enable`, { method: "POST", body: { algorithm, nsec3 } }),
    onSuccess: (d) => {
      set(d);
      setEnableOpen(false);
      toast.success("DNSSEC enabled", "Add the DS record at your registrar to complete the chain of trust.");
    },
  });
  const disable = useMutation({
    mutationFn: () => api<DnssecInfo>(`/orgs/${orgId}/zones/${zone!.id}/dnssec/disable`, { method: "POST" }),
    onSuccess: (d) => {
      set(d);
      setDisabling(false);
      toast.success("DNSSEC disabled");
    },
    onError: (e) => toast.error(e),
  });
  const addKey = useMutation({
    mutationFn: () => api<DnssecInfo>(`/orgs/${orgId}/zones/${zone!.id}/dnssec/keys`, { method: "POST", body: { keytype, algorithm, active: false, published: true } }),
    onSuccess: (d) => {
      set(d);
      setAddOpen(false);
      toast.success("Key added", "The key is published but inactive. Activate it when you are ready to roll over.");
    },
  });
  const keyAction = useMutation({
    mutationFn: ({ k, action }: { k: CryptoKey; action: "activate" | "deactivate" | "delete" }) =>
      action === "delete"
        ? api<DnssecInfo>(`/orgs/${orgId}/zones/${zone!.id}/dnssec/keys/${k.id}`, { method: "DELETE" })
        : api<DnssecInfo>(`/orgs/${orgId}/zones/${zone!.id}/dnssec/keys/${k.id}`, { method: "PATCH", body: { active: action === "activate" } }),
    onSuccess: (d) => {
      set(d);
      setDeletingKey(null);
    },
    onError: (e) => toast.error(e),
  });

  if (!zone) return null;
  const editable = can("zones.edit") && zone.kind !== "Slave";
  const d = info.data;
  const primaryDS = d?.ds.find((x) => parseDS(x).digestType === "2") ?? d?.ds[0];
  const ds = primaryDS ? parseDS(primaryDS) : null;
  const ksk = d?.keys.find((k) => k.active && (k.keytype === "ksk" || k.keytype === "csk"));

  const columns: Column<CryptoKey>[] = [
    { key: "id", header: "ID", width: "60px", render: (k) => <Mono>{k.id}</Mono> },
    { key: "type", header: "Type", width: "80px", render: (k) => <Badge variant="outline">{k.keytype.toUpperCase()}</Badge> },
    { key: "alg", header: "Algorithm", width: "30%", render: (k) => <span>{k.algorithm}</span> },
    { key: "bits", header: "Bits", width: "80px", render: (k) => <span className="text-kumo-subtle">{k.bits}</span> },
    {
      key: "state",
      header: "State",
      render: (k) => (
        <div className="flex gap-1.5">
          <Badge variant={k.active ? "success" : "neutral"}>{k.active ? "Active" : "Inactive"}</Badge>
          {k.published && <Badge variant="neutral">Published</Badge>}
        </div>
      ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "70px",
      align: "right",
      render: (k) =>
        editable ? (
          <ActionMenu
            items={[
              { key: "toggle", label: k.active ? "Deactivate" : "Activate", onSelect: () => keyAction.mutate({ k, action: k.active ? "deactivate" : "activate" }) },
              { key: "delete", label: "Delete key", danger: true, separatorBefore: true, onSelect: () => setDeletingKey(k) },
            ]}
          />
        ) : null,
    },
  ];

  return (
    <div className="grid max-w-5xl gap-6">
      <PageHeader title="DNSSEC" description="Cryptographically sign this zone so resolvers can detect forged responses." />
      {info.error && <Banner variant="error" description={errorMessage(info.error)} />}

      <Section>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className={`flex size-11 items-center justify-center rounded-xl ${d?.enabled ? "bg-kumo-success-tint text-kumo-success" : "bg-kumo-tint text-kumo-subtle"}`}>
              {d?.enabled ? <LockKeyIcon size={22} weight="fill" /> : <LockKeyOpenIcon size={22} />}
            </span>
            <div className="grid gap-0.5">
              <Text variant="heading" as="h2">
                DNSSEC is {d?.enabled ? "enabled" : "disabled"}
              </Text>
              <Text variant="secondary">
                {d?.enabled
                  ? `Signed with ${ksk?.algorithm ?? "an active key"}${d.nsec3param ? ", NSEC3" : ", NSEC"}.`
                  : zone.kind === "Slave"
                    ? "Secondary zones are signed by their primary server."
                    : "Responses for this zone are not signed."}
              </Text>
            </div>
          </div>
          {editable &&
            (d?.enabled ? (
              <Button variant="secondary-destructive" onClick={() => setDisabling(true)}>
                Disable DNSSEC
              </Button>
            ) : (
              <Button variant="primary" icon={<LockKeyIcon />} onClick={() => setEnableOpen(true)}>
                Enable DNSSEC
              </Button>
            ))}
        </div>
      </Section>

      {d?.enabled && ds && (
        <Section
          title="DS record for your registrar"
          description={`Add this DS record at the registrar for ${stripDot(zone.name)} to complete the chain of trust. Many registrars ask for each field separately.`}
        >
          <div className="divide-y divide-kumo-line">
            <DetailRow label="DS record">
              <ClipboardText text={`${zone.name} 3600 IN DS ${primaryDS}`} size="sm" />
            </DetailRow>
            <DetailRow label="Key tag">
              <Mono>{ds.keyTag}</Mono>
            </DetailRow>
            <DetailRow label="Algorithm">
              <Mono>{ds.algorithm}</Mono>
            </DetailRow>
            <DetailRow label="Digest type">
              <Mono>
                {ds.digestType} ({digestNames[ds.digestType] ?? "Unknown"})
              </Mono>
            </DetailRow>
            <DetailRow label="Digest">
              <ClipboardText text={ds.digest} size="sm" />
            </DetailRow>
            {ksk?.dnskey && (
              <DetailRow label="Public key (DNSKEY)">
                <ClipboardText text={ksk.dnskey} size="sm" />
              </DetailRow>
            )}
          </div>
          {zone.status !== "active" && (
            <div className="mt-4">
              <Banner variant="secondary" size="sm" icon={<InfoIcon weight="fill" />} description="Add the DS record only after your nameservers have been updated and the zone is active." />
            </div>
          )}
        </Section>
      )}

      {d && d.keys.length > 0 && (
        <Section
          padded={false}
          title="Signing keys"
          actions={
            editable && (
              <Button size="sm" icon={<PlusIcon />} onClick={() => setAddOpen(true)}>
                Add key
              </Button>
            )
          }
        >
          <VirtualTable ariaLabel="Signing keys" rows={d.keys} columns={columns} rowKey={(k) => String(k.id)} maxHeight="360px" />
        </Section>
      )}

      <Dialog.Root open={enableOpen} onOpenChange={setEnableOpen}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">Enable DNSSEC</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <div className="grid gap-4">
            <VirtualSelect label="Algorithm" options={dnssecAlgorithms} value={algorithm} onChange={setAlgorithm} description="ECDSA P-256 is widely supported and produces small responses." />
            <Switch label="Use NSEC3 (hashed denial of existence, prevents zone walking)" checked={nsec3} onCheckedChange={(v: boolean) => setNsec3(v)} />
            {enable.error && <Banner variant="error" size="sm" description={errorMessage(enable.error)} />}
            <div className="flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button variant="primary" loading={enable.isPending} onClick={() => enable.mutate()}>
                Enable DNSSEC
              </Button>
            </div>
          </div>
        </Dialog>
      </Dialog.Root>

      <Dialog.Root open={addOpen} onOpenChange={setAddOpen}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">Add signing key</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <div className="grid gap-4">
            <VirtualSelect
              label="Key type"
              options={[
                { value: "zsk", label: "ZSK", description: "Zone signing key" },
                { value: "ksk", label: "KSK", description: "Key signing key, referenced by the DS record" },
                { value: "csk", label: "CSK", description: "Combined signing key" },
              ]}
              value={keytype}
              onChange={setKeytype}
            />
            <VirtualSelect label="Algorithm" options={dnssecAlgorithms} value={algorithm} onChange={setAlgorithm} />
            <Text variant="secondary" size="sm">
              New keys are published but inactive, so resolvers can cache them before you activate them during a rollover.
            </Text>
            {addKey.error && <Banner variant="error" size="sm" description={errorMessage(addKey.error)} />}
            <div className="flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button variant="primary" loading={addKey.isPending} onClick={() => addKey.mutate()}>
                Add key
              </Button>
            </div>
          </div>
        </Dialog>
      </Dialog.Root>

      <ConfirmDialog
        open={disabling}
        onOpenChange={setDisabling}
        title="Disable DNSSEC"
        description="Remove the DS record at your registrar first and wait for its TTL to expire. Disabling signing while a DS record exists makes the domain unresolvable for validating resolvers."
        confirmText={stripDot(zone.name)}
        confirmLabel="Disable DNSSEC"
        loading={disable.isPending}
        onConfirm={() => disable.mutate()}
      />
      <ConfirmDialog
        open={!!deletingKey}
        onOpenChange={(o) => !o && setDeletingKey(null)}
        title="Delete signing key"
        description="Deleting an active key that a DS record references will break validation."
        confirmLabel="Delete key"
        loading={keyAction.isPending}
        onConfirm={() => deletingKey && keyAction.mutate({ k: deletingKey, action: "delete" })}
      />
    </div>
  );
}
