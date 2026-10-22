// Minimal RFC 3492 punycode decoder for displaying internationalized domain names.
const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let k = 0;
  delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
  return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
}

function digit(cp: number): number {
  if (cp - 48 < 10) return cp - 22;
  if (cp - 65 < 26) return cp - 65;
  if (cp - 97 < 26) return cp - 97;
  return base;
}

export function punycodeDecode(input: string): string {
  const output: number[] = [];
  let n = initialN, i = 0, bias = initialBias;
  let basic = input.lastIndexOf("-");
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (index >= input.length) throw new Error("bad input");
      const d = digit(input.charCodeAt(index++));
      if (d >= base) throw new Error("bad input");
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/** Converts an ASCII (punycode) domain to its Unicode form for display. */
export function toUnicode(domain: string): string {
  return domain
    .split(".")
    .map((label) => {
      if (!label.toLowerCase().startsWith("xn--")) return label;
      try {
        return punycodeDecode(label.slice(4));
      } catch {
        return label;
      }
    })
    .join(".");
}

/** Display form of a zone name: no trailing dot, Unicode labels. */
export function displayDomain(name: string): string {
  return toUnicode(name.replace(/\.$/, ""));
}
