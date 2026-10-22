import { useEffect, useMemo, useState } from "react";
import { Banner, Button, Checkbox, Input, InputGroup, Switch, Text, cn } from "@cloudflare/kumo";
import { VirtualSelect } from "./VirtualSelect";
import { recordTypes, recordTypeMap, ttlOptions, displayContent, ptrName, isReverseZone } from "../lib/dns";
import { relativeName, stripDot } from "../lib/format";
import { displayDomain } from "../lib/idn";
import { ApiError, errorMessage } from "../lib/api";
import type { DnsRecord } from "../lib/types";

export interface RecordDraft {
  name: string;
  type: string;
  ttl: number;
  content: string;
  comment: string;
  disabled: boolean;
  create_ptr?: boolean;
}

const widthClass = { sm: "md:col-span-1", md: "md:col-span-2", lg: "md:col-span-3", full: "md:col-span-4" } as const;

export function draftFromRecord(r: DnsRecord, zone: string): RecordDraft {
  return { name: relativeName(r.name, zone), type: r.type, ttl: r.ttl, content: displayContent(r.type, r.content), comment: r.comment, disabled: r.disabled };
}

interface Props {
  zone: string;
  initial?: RecordDraft;
  onSubmit: (d: RecordDraft) => void;
  onCancel: () => void;
  submitting?: boolean;
  error?: unknown;
  submitLabel: string;
  /** Types allowed by the administrator for this zone (empty = all). */
  allowedTypes?: string[];
  /** Whether the organization has reverse zones, enabling the PTR option. */
  hasReverseZones?: boolean;
  autoPtrDefault?: boolean;
}

export function RecordForm({ zone, initial, onSubmit, onCancel, submitting, error, submitLabel, allowedTypes, hasReverseZones, autoPtrDefault }: Props) {
  const reverse = isReverseZone(zone);
  const [type, setType] = useState(initial?.type ?? (reverse ? "PTR" : "A"));
  const [name, setName] = useState(initial?.name ?? "");
  const [content, setContent] = useState(initial?.content ?? "");
  const [ttl, setTtl] = useState(initial?.ttl ?? 1);
  const [comment, setComment] = useState(initial?.comment ?? "");
  const [disabled, setDisabled] = useState(initial?.disabled ?? false);
  const [createPtr, setCreatePtr] = useState(autoPtrDefault ?? false);
  const [ip, setIp] = useState("");
  const spec = recordTypeMap[type];
  const [fields, setFields] = useState<Record<string, string>>(() => (spec?.parse && initial?.content ? spec.parse(initial.content) : {}));

  useEffect(() => {
    if (spec?.parse)
      setFields(
        initial && initial.type === type
          ? spec.parse(initial.content)
          : (spec.fields?.reduce((a, f) => ({ ...a, [f.key]: f.kind === "select" ? (f.options?.[0]?.value ?? "") : "" }), {}) ?? {}),
      );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type]);

  const typeOptions = useMemo(
    () =>
      recordTypes
        .filter((t) => !allowedTypes?.length || allowedTypes.includes(t.type) || t.type === initial?.type)
        .map((t) => ({ value: t.type, label: t.type, description: t.description, keywords: t.description })),
    [allowedTypes, initial?.type],
  );
  const ttlOpts = useMemo(() => {
    const opts = ttlOptions.map((t) => ({ value: t.value, label: t.label }));
    if (!opts.some((o) => o.value === ttl)) opts.push({ value: ttl, label: `${ttl} sec` });
    return opts;
  }, [ttl]);

  const fe = (f: string) => (error instanceof ApiError ? error.fields[f] : undefined);
  const generic = error && !(error instanceof ApiError && Object.keys(error.fields).length > 0) ? errorMessage(error) : null;
  const zoneLabel = stripDot(zone);
  const shown = displayDomain(zone);
  const fqdn = !name || name === "@" ? zoneLabel : name.endsWith(".") ? stripDot(name) : `${name}.${zoneLabel}`;

  // Reverse-zone helper: derive the owner name from an IP address.
  const ipName = ip ? ptrName(ip) : null;
  const ipInZone = ipName && (ipName === zone || ipName.endsWith("." + zone));
  useEffect(() => {
    if (ipName && ipInZone) setName(relativeName(ipName, zone));
  }, [ipName, ipInZone, zone]);

  const submit = () => {
    const finalContent = spec?.compose ? spec.compose(fields) : content;
    const showPtr = !reverse && hasReverseZones && (type === "A" || type === "AAAA");
    onSubmit({ name: name || "@", type, ttl, content: finalContent, comment, disabled, ...(showPtr ? { create_ptr: createPtr } : {}) });
  };

  return (
    <form
      className="grid gap-5"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <div className="grid gap-4 md:grid-cols-[150px_minmax(0,1fr)_150px]">
        <VirtualSelect label="Type" options={typeOptions} value={type} onChange={setType} searchable popupWidth={340} />
        <InputGroup label="Name" error={fe("name") ? { message: fe("name"), match: true } : undefined} description={`Resolves as ${displayDomain(fqdn)}`}>
          <InputGroup.Input value={name} onChange={(e) => setName(e.target.value)} placeholder="@ for the root" autoFocus={!initial} spellCheck={false} aria-label="Name" />
          <InputGroup.Addon align="end" className="max-w-[45%] truncate text-kumo-subtle">
            .{shown}
          </InputGroup.Addon>
        </InputGroup>
        <VirtualSelect label="TTL" options={ttlOpts} value={ttl} onChange={setTtl} />
      </div>

      {reverse && type === "PTR" && (
        <Input
          label="IP address"
          required={false}
          placeholder={zone.endsWith("ip6.arpa.") ? "2001:db8::10" : "192.0.2.10"}
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          description={ip && !ipName ? "Not a valid IP address" : ip && !ipInZone ? `This address is not inside ${zoneLabel}` : "Type an address to fill in the reverse name automatically."}
          spellCheck={false}
        />
      )}

      {spec?.fields ? (
        <div className="grid gap-4 md:grid-cols-4">
          {spec.fields.map((f) => (
            <div key={f.key} className={cn(widthClass[f.width ?? "md"])}>
              {f.kind === "select" ? (
                <VirtualSelect
                  label={f.label}
                  options={(f.options ?? []).map((o) => ({ value: o.value, label: o.label }))}
                  value={fields[f.key] ?? ""}
                  onChange={(v) => setFields({ ...fields, [f.key]: v })}
                />
              ) : (
                <Input
                  label={f.label}
                  type={f.kind === "number" ? "number" : "text"}
                  placeholder={f.placeholder}
                  value={fields[f.key] ?? ""}
                  onChange={(e) => setFields({ ...fields, [f.key]: e.target.value })}
                  spellCheck={false}
                />
              )}
            </div>
          ))}
          {fe("content") && (
            <div className="md:col-span-4">
              <Text variant="error">{fe("content")}</Text>
            </div>
          )}
        </div>
      ) : (
        <Input
          label={spec?.contentLabel ?? "Content"}
          placeholder={spec?.contentPlaceholder}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          spellCheck={false}
          className="font-mono"
          error={fe("content")}
          description={type === "TXT" ? "Enter the text as-is. Long values are split into 255-character strings automatically." : undefined}
        />
      )}

      <Input label="Comment" required={false} placeholder="Why this record exists" value={comment} onChange={(e) => setComment(e.target.value)} error={fe("comment")} />

      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <Switch label="Disabled" checked={disabled} onCheckedChange={(v: boolean) => setDisabled(v)} />
        {!reverse && hasReverseZones && (type === "A" || type === "AAAA") && (
          <Checkbox label="Create or update the matching PTR record" checked={createPtr} onCheckedChange={(v: boolean) => setCreatePtr(v)} />
        )}
      </div>

      {type === "CNAME" && (!name || name === "@") && (
        <Banner variant="alert" size="sm" description="CNAME records cannot exist at the root of a zone. Use an ALIAS record to point the apex at another hostname." />
      )}
      {type === "NS" && (!name || name === "@") && (
        <Banner
          variant="alert"
          size="sm"
          description="The zone's own NS records are managed through its nameserver set. Change them in zone settings, or enter a subdomain to delegate it."
        />
      )}
      {generic && <Banner variant="error" size="sm" description={generic} />}
      {fe("type") && <Text variant="error">{fe("type")}</Text>}

      <div className="flex justify-end gap-2 border-t border-kumo-line pt-4">
        <Button type="button" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" loading={submitting}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
