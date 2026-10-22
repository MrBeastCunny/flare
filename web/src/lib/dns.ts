export interface FieldSpec {
  key: string;
  label: string;
  placeholder?: string;
  kind?: "text" | "number" | "select" | "textarea";
  options?: { value: string; label: string }[];
  width?: "sm" | "md" | "lg" | "full";
  help?: string;
}

export interface RecordTypeSpec {
  type: string;
  description: string;
  fields?: FieldSpec[];
  compose?: (v: Record<string, string>) => string;
  parse?: (content: string) => Record<string, string>;
  contentLabel?: string;
  contentPlaceholder?: string;
}

const unquote = (s: string) => {
  const parts = s.match(/"((?:[^"\\]|\\.)*)"/g);
  if (!parts) return s;
  return parts.map((p) => p.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\")).join("");
};

const split = (s: string) => s.trim().split(/\s+/);

export const recordTypes: RecordTypeSpec[] = [
  { type: "A", description: "Maps a name to an IPv4 address", contentLabel: "IPv4 address", contentPlaceholder: "192.0.2.1" },
  { type: "AAAA", description: "Maps a name to an IPv6 address", contentLabel: "IPv6 address", contentPlaceholder: "2001:db8::1" },
  { type: "CNAME", description: "Aliases one name to another", contentLabel: "Target", contentPlaceholder: "www.example.com" },
  { type: "ALIAS", description: "CNAME-like alias allowed at the zone apex", contentLabel: "Target", contentPlaceholder: "lb.example.net" },
  {
    type: "MX",
    description: "Mail server for the domain",
    fields: [
      { key: "priority", label: "Priority", kind: "number", placeholder: "10", width: "sm" },
      { key: "target", label: "Mail server", placeholder: "mail.example.com", width: "lg" },
    ],
    compose: (v) => `${v.priority || "10"} ${v.target ?? ""}`,
    parse: (c) => {
      const [priority, target] = split(c);
      return { priority, target };
    },
  },
  {
    type: "TXT",
    description: "Free-form text, used for SPF, DKIM, DMARC and verification",
    contentLabel: "Content",
    contentPlaceholder: "v=spf1 include:_spf.example.net ~all",
  },
  {
    type: "SRV",
    description: "Locates services such as SIP or XMPP",
    fields: [
      { key: "priority", label: "Priority", kind: "number", placeholder: "10", width: "sm" },
      { key: "weight", label: "Weight", kind: "number", placeholder: "5", width: "sm" },
      { key: "port", label: "Port", kind: "number", placeholder: "5060", width: "sm" },
      { key: "target", label: "Target", placeholder: "sip.example.com", width: "lg" },
    ],
    compose: (v) => `${v.priority || "0"} ${v.weight || "0"} ${v.port || "0"} ${v.target ?? ""}`,
    parse: (c) => {
      const [priority, weight, port, target] = split(c);
      return { priority, weight, port, target };
    },
  },
  {
    type: "CAA",
    description: "Restricts which certificate authorities may issue certificates",
    fields: [
      { key: "flags", label: "Flags", kind: "number", placeholder: "0", width: "sm" },
      {
        key: "tag",
        label: "Tag",
        kind: "select",
        width: "md",
        options: [
          { value: "issue", label: "issue: allow issuance" },
          { value: "issuewild", label: "issuewild: allow wildcard issuance" },
          { value: "iodef", label: "iodef: report violations" },
        ],
      },
      { key: "value", label: "CA domain or URL", placeholder: "letsencrypt.org", width: "lg" },
    ],
    compose: (v) => `${v.flags || "0"} ${v.tag || "issue"} "${(v.value ?? "").replace(/"/g, "")}"`,
    parse: (c) => {
      const m = /^(\d+)\s+(\S+)\s+(.*)$/.exec(c.trim());
      return m ? { flags: m[1], tag: m[2], value: unquote(m[3]) } : { flags: "0", tag: "issue", value: "" };
    },
  },
  { type: "NS", description: "Delegates a subdomain to other nameservers", contentLabel: "Nameserver", contentPlaceholder: "ns1.example.net" },
  { type: "PTR", description: "Reverse DNS pointer", contentLabel: "Domain name", contentPlaceholder: "host.example.com" },
  {
    type: "HTTPS",
    description: "Service binding for HTTPS endpoints",
    contentLabel: "Priority, target and parameters",
    contentPlaceholder: '1 . alpn="h3,h2"',
  },
  { type: "SVCB", description: "General service binding", contentLabel: "Priority, target and parameters", contentPlaceholder: "1 svc.example.com. port=8443" },
  {
    type: "TLSA",
    description: "DANE certificate association",
    fields: [
      { key: "usage", label: "Usage", kind: "number", placeholder: "3", width: "sm" },
      { key: "selector", label: "Selector", kind: "number", placeholder: "1", width: "sm" },
      { key: "matching", label: "Matching type", kind: "number", placeholder: "1", width: "sm" },
      { key: "data", label: "Certificate data", placeholder: "hex digest", width: "lg" },
    ],
    compose: (v) => `${v.usage || "3"} ${v.selector || "1"} ${v.matching || "1"} ${v.data ?? ""}`,
    parse: (c) => {
      const [usage, selector, matching, ...rest] = split(c);
      return { usage, selector, matching, data: rest.join("") };
    },
  },
  {
    type: "SSHFP",
    description: "SSH host key fingerprint",
    fields: [
      { key: "algorithm", label: "Algorithm", kind: "number", placeholder: "4", width: "sm" },
      { key: "fptype", label: "Fingerprint type", kind: "number", placeholder: "2", width: "sm" },
      { key: "fingerprint", label: "Fingerprint", placeholder: "hex", width: "lg" },
    ],
    compose: (v) => `${v.algorithm || "4"} ${v.fptype || "2"} ${v.fingerprint ?? ""}`,
    parse: (c) => {
      const [algorithm, fptype, fingerprint] = split(c);
      return { algorithm, fptype, fingerprint };
    },
  },
  { type: "DS", description: "Delegation signer for a signed child zone", contentLabel: "Key tag, algorithm, digest type, digest", contentPlaceholder: "2371 13 2 1F987CC6583E92DF0890718C42" },
  { type: "NAPTR", description: "Naming authority pointer", contentLabel: "Content", contentPlaceholder: '100 10 "U" "E2U+sip" "!^.*$!sip:info@example.com!" .' },
  { type: "DNAME", description: "Redirects an entire subtree", contentLabel: "Target", contentPlaceholder: "example.net" },
  { type: "LOC", description: "Geographic location", contentLabel: "Location", contentPlaceholder: "51 30 12.748 N 0 7 39.611 W 0.00m" },
  { type: "URI", description: "Maps a name to a URI", contentLabel: "Priority, weight, target", contentPlaceholder: '10 1 "https://example.com/"' },
  { type: "CERT", description: "Stores certificates or CRLs", contentLabel: "Content", contentPlaceholder: "PGP 0 0 base64data" },
  { type: "SMIMEA", description: "S/MIME certificate association", contentLabel: "Content", contentPlaceholder: "3 1 1 hexdata" },
  { type: "OPENPGPKEY", description: "OpenPGP public key", contentLabel: "Base64 key", contentPlaceholder: "mQENBF..." },
  { type: "HINFO", description: "Host information", contentLabel: "CPU and OS", contentPlaceholder: '"x86_64" "Linux"' },
  { type: "RP", description: "Responsible person", contentLabel: "Mailbox and TXT name", contentPlaceholder: "admin.example.com. info.example.com." },
  { type: "SPF", description: "Legacy SPF record type (use TXT instead)", contentLabel: "Content", contentPlaceholder: "v=spf1 -all" },
];

export const recordTypeMap = Object.fromEntries(recordTypes.map((t) => [t.type, t]));

export const ttlOptions: { value: number; label: string }[] = [
  { value: 1, label: "Auto" },
  { value: 60, label: "1 min" },
  { value: 120, label: "2 min" },
  { value: 300, label: "5 min" },
  { value: 600, label: "10 min" },
  { value: 900, label: "15 min" },
  { value: 1800, label: "30 min" },
  { value: 3600, label: "1 hr" },
  { value: 7200, label: "2 hrs" },
  { value: 18000, label: "5 hrs" },
  { value: 43200, label: "12 hrs" },
  { value: 86400, label: "1 day" },
  { value: 172800, label: "2 days" },
  { value: 604800, label: "1 week" },
];

/** Strips quoting from TXT content for display. */
export function displayContent(type: string, content: string): string {
  if (type === "TXT" || type === "SPF") return unquote(content);
  return content;
}

export const dnssecAlgorithms = [
  { value: "ecdsap256sha256", label: "ECDSA P-256 with SHA-256 (13)" },
  { value: "ecdsap384sha384", label: "ECDSA P-384 with SHA-384 (14)" },
  { value: "ed25519", label: "Ed25519 (15)" },
  { value: "ed448", label: "Ed448 (16)" },
  { value: "rsasha256", label: "RSA/SHA-256 (8)" },
  { value: "rsasha512", label: "RSA/SHA-512 (10)" },
];

/** Splits a DS record into its parts for registrar forms. */
export function parseDS(ds: string) {
  const [keyTag, algorithm, digestType, ...digest] = ds.split(/\s+/);
  return { keyTag, algorithm, digestType, digest: digest.join("").toUpperCase() };
}

export function isReverseZone(name: string): boolean {
  const n = name.toLowerCase().replace(/\.$/, "");
  return n.endsWith(".in-addr.arpa") || n.endsWith(".ip6.arpa");
}

function expandIPv6(ip: string): string | null {
  if (!/^[0-9a-f:]+$/i.test(ip) || ip.split("::").length > 2) return null;
  const [head, tail] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail !== undefined ? (tail ? tail.split(":") : []) : [];
  const missing = 8 - h.length - t.length;
  if ((tail === undefined && h.length !== 8) || missing < 0) return null;
  const groups = [...h, ...Array(tail !== undefined ? missing : 0).fill("0"), ...t];
  if (groups.some((g) => g.length === 0 || g.length > 4)) return null;
  return groups.map((g) => g.padStart(4, "0")).join("");
}

/** Reverse (PTR) owner name for an IP address, fully qualified, or null when invalid. */
export function ptrName(ip: string): string | null {
  const v = ip.trim();
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
  if (v4) {
    const parts = v4.slice(1).map(Number);
    if (parts.some((p) => p > 255)) return null;
    return `${parts.reverse().join(".")}.in-addr.arpa.`;
  }
  const hex = expandIPv6(v);
  return hex ? `${hex.split("").reverse().join(".")}.ip6.arpa.` : null;
}

/** Reverse zone name for a CIDR on an octet or nibble boundary, or null. */
export function reverseZoneForCIDR(cidr: string): string | null {
  const [ip, lenStr] = cidr.trim().split("/");
  const len = Number(lenStr);
  if (!ip || !Number.isInteger(len)) return null;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    if (len % 8 !== 0 || len < 8 || len > 24) return null;
    return ip.split(".").slice(0, len / 8).reverse().join(".") + ".in-addr.arpa";
  }
  const hex = expandIPv6(ip);
  if (!hex || len % 4 !== 0 || len < 4 || len > 124) return null;
  return hex.slice(0, len / 4).split("").reverse().join(".") + ".ip6.arpa";
}
