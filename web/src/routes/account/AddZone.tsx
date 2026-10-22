import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Input, InputArea, LayerCard, Radio, Switch, TagInput, Text, Collapsible } from "@cloudflare/kumo";
import { MagnifyingGlassIcon, FileTextIcon, ArrowRightIcon, CheckCircleIcon, ProhibitIcon } from "@phosphor-icons/react";
import { PageHeader, Section, Mono } from "../../components/ui";
import { Steps } from "../../components/Steps";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { NameserverInstructions } from "../../components/NameserverInstructions";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys, useOrgId, usePerms, useMe } from "../../lib/queries";
import { displayContent, isReverseZone, reverseZoneForCIDR } from "../../lib/dns";
import { formatTTL, relativeName, stripDot } from "../../lib/format";
import type { ParsedRecord, Zone, ZoneTemplate } from "../../lib/types";

interface ScanResult {
  name: string;
  records: ParsedRecord[];
  current_nameservers: string[];
  skipped_addresses?: number;
}

type Source = "scan" | "file" | "empty";

const recKey = (r: ParsedRecord) => `${r.name}|${r.type}|${r.content}`;

export default function AddZone() {
  const orgId = useOrgId();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const me = useMe();
  const { can, role } = usePerms(orgId);
  const [params] = useSearchParams();
  const [step, setStep] = useState(0);
  const [domain, setDomain] = useState(params.get("domain") ?? "");
  const [kind, setKind] = useState<Zone["kind"]>("Native");
  const [masters, setMasters] = useState<string[]>([]);
  const [nsSetId, setNsSetId] = useState<string>("");
  const [dnssec, setDnssec] = useState(false);
  const [skipVerification, setSkipVerification] = useState(false);
  const [templateId, setTemplateId] = useState("");
  const reverseZone = domain.includes("/") ? reverseZoneForCIDR(domain) : null;
  const isReverse = !!reverseZone || isReverseZone(domain);
  const templates = useQuery({ queryKey: ["org", orgId, "templates"], queryFn: () => api<ZoneTemplate[]>(`/orgs/${orgId}/templates`) });
  const [source, setSource] = useState<Source>("scan");
  const [zoneFile, setZoneFile] = useState("");
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [created, setCreated] = useState<{ zone: Zone; imported_records: number; dnssec_error: string } | null>(null);

  const nsSets = useQuery({
    queryKey: keys.nsSets(orgId),
    queryFn: () => api<{ id: string; name: string; nameservers: string[]; is_default: boolean }[]>(`/orgs/${orgId}/nameserver-sets`),
  });

  const runScan = useMutation({
    mutationFn: () => api<ScanResult>(`/orgs/${orgId}/zones/scan`, { method: "POST", body: { name: domain } }),
    onSuccess: (d) => {
      setScan(d);
      setSelected(new Set(d.records.map(recKey)));
      setStep(1);
    },
  });

  const create = useMutation({
    mutationFn: () => {
      let records: ParsedRecord[] = [];
      if (source === "scan" && scan) records = scan.records.filter((r) => selected.has(recKey(r)));
      return api<{ zone: Zone; imported_records: number; dnssec_error: string }>(`/orgs/${orgId}/zones`, {
        method: "POST",
        body: {
          name: domain,
          kind,
          masters: kind === "Slave" ? masters : [],
          nameserver_set_id: nsSetId || null,
          records,
          dnssec: kind !== "Slave" ? dnssec : false,
          skip_verification: skipVerification || isReverse,
          template_id: templateId || null,
        },
      });
    },
    onSuccess: async (d) => {
      if (source === "file" && zoneFile.trim()) {
        await api(`/orgs/${orgId}/zones/${d.zone.id}/import`, { method: "POST", body: { text: zoneFile, mode: "merge" } })
          .then((r) => {
            const added = (r as { added: number }).added;
            d.imported_records += added;
          })
          .catch((e) => {
            d.dnssec_error = (d.dnssec_error ? d.dnssec_error + " " : "") + "Zone file import failed: " + errorMessage(e);
          });
      }
      setCreated(d);
      setStep(2);
      void qc.invalidateQueries({ queryKey: keys.zones(orgId) });
      void qc.invalidateQueries({ queryKey: keys.org(orgId) });
      void qc.invalidateQueries({ queryKey: keys.orgOverview(orgId) });
    },
  });

  const columns: Column<ParsedRecord>[] = useMemo(
    () => [
      { key: "type", header: "Type", width: "90px", render: (r) => <Badge variant="neutral">{r.type}</Badge> },
      { key: "name", header: "Name", width: "28%", render: (r) => <Mono>{relativeName(r.name, scan?.name ?? domain)}</Mono> },
      { key: "content", header: "Content", render: (r) => <Mono className="text-kumo-subtle">{displayContent(r.type, r.content)}</Mono> },
      { key: "ttl", header: "TTL", width: "90px", render: (r) => <span className="text-kumo-subtle">{formatTTL(r.ttl)}</span> },
    ],
    [scan, domain],
  );

  const isAdmin = role === "owner" || role === "admin" || me.data?.user.is_superadmin;
  const defaultSet = nsSets.data?.find((s) => s.is_default);

  if (!can("zones.create") && role) {
    return (
      <div className="py-16 text-center">
        <ProhibitIcon size={40} className="mx-auto text-kumo-inactive" />
        <Text variant="heading" as="h1">
          You cannot add domains
        </Text>
        <Text variant="secondary">Ask an organization administrator for the DNS Editor role.</Text>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader title="Add a domain" description="Bring an existing domain to authoritative DNS hosted on your PowerDNS servers." />
      <div className="mb-6">
        <Steps steps={["Enter domain", "Review DNS records", "Change nameservers"]} current={step} />
      </div>

      {step === 0 && (
        <Section>
          <form
            className="grid gap-5"
            onSubmit={(e) => {
              e.preventDefault();
              if (kind === "Slave" || kind === "Consumer" || source !== "scan" || isReverse) {
                if (isReverse) setSource("empty");
                setScan({ name: domain, records: [], current_nameservers: [] });
                setStep(1);
              } else {
                runScan.mutate();
              }
            }}
          >
            <Input
              label="Domain"
              size="lg"
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              autoFocus
              error={fieldError(runScan.error, "name")}
              description={
                reverseZone
                  ? `Creates the reverse zone ${reverseZone}.`
                  : domain.includes("/")
                    ? "Reverse zones need an IPv4 /8, /16 or /24, or an IPv6 prefix that is a multiple of 4."
                    : "Enter the registered domain, or an address range such as 192.0.2.0/24 for a reverse zone."
              }
            />
            {kind !== "Slave" && kind !== "Consumer" && !isReverse && (
              <Radio.Group legend="Existing DNS records" value={source} onValueChange={(v) => setSource(v as Source)} appearance="card">
                <Radio.Item
                  value="scan"
                  label={
                    <span className="grid gap-0.5">
                      <span className="flex items-center gap-2 font-medium">
                        <MagnifyingGlassIcon /> Quick scan (recommended)
                      </span>
                      <span className="text-sm text-kumo-subtle">Look up common records so your site and email keep working.</span>
                    </span>
                  }
                />
                <Radio.Item
                  value="file"
                  label={
                    <span className="grid gap-0.5">
                      <span className="flex items-center gap-2 font-medium">
                        <FileTextIcon /> Import a zone file
                      </span>
                      <span className="text-sm text-kumo-subtle">Paste a BIND-format export from your current provider.</span>
                    </span>
                  }
                />
                <Radio.Item
                  value="empty"
                  label={
                    <span className="grid gap-0.5">
                      <span className="font-medium">Start with no records</span>
                      <span className="text-sm text-kumo-subtle">Only the SOA and NS records are created.</span>
                    </span>
                  }
                />
              </Radio.Group>
            )}

            <Collapsible.Root>
              <Collapsible.DefaultTrigger>Advanced options</Collapsible.DefaultTrigger>
              <Collapsible.DefaultPanel>
                <div className="grid gap-4 pt-3">
                  <VirtualSelect
                    label="Zone type"
                    options={[
                      { value: "Native", label: "Primary (native replication)", description: "Recommended. Replicated by your database backend." },
                      { value: "Master", label: "Primary (send NOTIFY and AXFR)", description: "Use when external secondaries transfer from you." },
                      { value: "Slave", label: "Secondary", description: "Transfer the zone from another primary server." },
                      { value: "Producer", label: "Catalog producer", description: "A catalog zone listing member zones for secondaries." },
                      { value: "Consumer", label: "Catalog consumer", description: "Provision member zones from a remote catalog." },
                    ]}
                    value={kind}
                    onChange={(v) => setKind(v as typeof kind)}
                  />
                  {templates.data && templates.data.length > 0 && kind !== "Slave" && kind !== "Consumer" && (
                    <VirtualSelect
                      label="Template"
                      required={false}
                      description="Add a predefined set of records, such as mail or verification records."
                      options={[{ value: "", label: "No template" }, ...templates.data.map((t) => ({ value: t.id, label: t.name, description: `${t.records.length} records` }))]}
                      value={templateId}
                      onChange={setTemplateId}
                    />
                  )}
                  {(kind === "Slave" || kind === "Consumer") && (
                    <TagInput
                      label="Primary server addresses"
                      description="IP addresses (optionally with :port) the zone is transferred from."
                      placeholder="192.0.2.53"
                      value={masters}
                      onValueChange={(v: string[]) => setMasters(v)}
                    />
                  )}
                  {(nsSets.data?.length ?? 0) > 1 && (
                    <VirtualSelect
                      label="Nameserver set"
                      options={(nsSets.data ?? []).map((s) => ({ value: s.id, label: s.name + (s.is_default ? " (default)" : ""), description: s.nameservers.map(stripDot).join(", ") }))}
                      value={nsSetId || defaultSet?.id || ""}
                      onChange={setNsSetId}
                    />
                  )}
                  {kind !== "Slave" && (
                    <Switch label="Sign the zone with DNSSEC" checked={dnssec} onCheckedChange={(v: boolean) => setDnssec(v)} />
                  )}
                  {isAdmin && (
                    <Switch
                      label="Activate immediately without verifying the delegation (internal or lab zones)"
                      checked={skipVerification}
                      onCheckedChange={(v: boolean) => setSkipVerification(v)}
                    />
                  )}
                </div>
              </Collapsible.DefaultPanel>
            </Collapsible.Root>

            {runScan.error && !fieldError(runScan.error, "name") && <Banner variant="error" size="sm" description={errorMessage(runScan.error)} />}
            <div>
              <Button type="submit" variant="primary" icon={<ArrowRightIcon />} loading={runScan.isPending} disabled={!domain.includes(".") && !reverseZone}>
                {runScan.isPending ? "Scanning DNS records" : "Continue"}
              </Button>
            </div>
          </form>
        </Section>
      )}

      {step === 1 && scan && (
        <div className="grid gap-5">
          {kind === "Slave" ? (
            <Section title="Secondary zone" description="Records are transferred from the primary servers after creation.">
              <Text>
                Primaries: <Mono>{masters.join(", ") || "none"}</Mono>
              </Text>
            </Section>
          ) : source === "scan" ? (
            <>
              {!!scan.skipped_addresses && (
                <Banner
                  variant="alert"
                  title="Some lookups returned fake addresses"
                  description={`${scan.skipped_addresses} A or AAAA answers pointed at reserved addresses such as 198.18.0.0/15 and were left out. Something between Flare and its DNS resolver is rewriting answers, usually a proxy or VPN in fake-IP mode. Review the remaining records, or import a zone file exported from the current provider instead.`}
                />
              )}
              <Section
                padded={false}
                title={`${scan.records.length} records found`}
                description={`We looked up common records for ${stripDot(scan.name)}. Deselect anything you do not want to import. You can edit records after the domain is added.`}
              >
                <VirtualTable
                  ariaLabel="Discovered records"
                  rows={scan.records}
                  columns={columns}
                  rowKey={recKey}
                  selection={{ selected, onChange: setSelected }}
                  maxHeight="420px"
                  empty={
                    <div className="px-5 py-10 text-center text-kumo-subtle">
                      No records were found. The domain may be new, or its current provider blocks lookups.
                    </div>
                  }
                />
              </Section>
            </>
          ) : source === "file" ? (
            <Section title="Zone file" description="Paste the contents of the exported zone. SOA and apex NS records are replaced by your own.">
              <InputArea
                aria-label="Zone file"
                value={zoneFile}
                onValueChange={setZoneFile}
                className="min-h-72 font-mono text-sm"
                placeholder={"$ORIGIN example.com.\n$TTL 3600\n@    IN A     192.0.2.10\nwww  IN CNAME example.com.\n@    IN MX 10 mail.example.com."}
              />
            </Section>
          ) : (
            <Section title="No records">
              <Text variant="secondary">The zone will start with only SOA and NS records.</Text>
            </Section>
          )}
          {create.error && <Banner variant="error" description={errorMessage(create.error)} />}
          <div className="flex justify-between">
            <Button variant="ghost" onClick={() => setStep(0)}>
              Back
            </Button>
            <Button variant="primary" loading={create.isPending} onClick={() => create.mutate()}>
              {source === "scan" && kind !== "Slave" ? `Add domain with ${selected.size} records` : "Add domain"}
            </Button>
          </div>
        </div>
      )}

      {step === 2 && created && (
        <div className="grid gap-5">
          <LayerCard className="px-6 py-5">
            <div className="flex items-start gap-3">
              <span className="flex h-lh items-center">
                <CheckCircleIcon size={22} weight="fill" className="text-kumo-success" />
              </span>
              <div className="grid gap-1">
                <Text variant="heading" as="h2">
                  {stripDot(created.zone.name)} has been added
                </Text>
                <Text variant="secondary">
                  {created.imported_records > 0 ? `${created.imported_records} records imported. ` : ""}
                  {created.zone.status === "active"
                    ? "The zone is active."
                    : created.zone.kind === "Slave"
                      ? "Allow zone transfers to your nameservers on the primary server."
                      : "One last step: point the domain at your nameservers."}
                </Text>
              </div>
            </div>
          </LayerCard>
          {created.dnssec_error && <Banner variant="alert" description={created.dnssec_error} />}
          <Section>
            <NameserverInstructions zone={created.zone} currentNameservers={scan?.current_nameservers} />
          </Section>
          <div className="flex justify-end gap-2">
            <Button onClick={() => navigate(`/${orgId}/${stripDot(created.zone.name)}/dns`)}>Review DNS records</Button>
            <Button variant="primary" onClick={() => navigate(`/${orgId}/${stripDot(created.zone.name)}`)}>
              Go to overview
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
