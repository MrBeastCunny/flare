import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Banner, Button, ClipboardText, Input, Text } from "@cloudflare/kumo";
import { DownloadSimpleIcon, ShieldCheckIcon, WarningIcon } from "@phosphor-icons/react";
import { api, errorMessage, fieldError } from "../lib/api";
import { VirtualList } from "./VirtualList";

interface SetupData {
  secret: string;
  otpauth_url: string;
  qr_code: string;
}

export function RecoveryCodes({ codes, account }: { codes: string[]; account: string }) {
  const text = `Recovery codes for ${account}\nEach code can be used once.\n\n${codes.join("\n")}\n`;
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="grid gap-4">
      <Banner
        variant="alert"
        icon={<WarningIcon weight="fill" />}
        title="Save these recovery codes"
        description="If you lose your authenticator device, each code lets you sign in once. They will not be shown again."
      />
      <div className="rounded-lg bg-kumo-recessed px-4 py-3 font-mono text-sm">
        <VirtualList ariaLabel="Recovery codes" items={codes} itemKey={(c) => c} divided={false} estimateSize={24} maxHeight={260} renderItem={(c) => <span className="block py-0.5">{c}</span>} />
      </div>
      <div className="flex gap-2">
        <Button icon={<DownloadSimpleIcon />} onClick={download}>
          Download
        </Button>
        <Button onClick={() => navigator.clipboard.writeText(codes.join("\n"))}>Copy</Button>
      </div>
    </div>
  );
}

/** Three-step authenticator app enrollment: scan, verify, save recovery codes. */
export function MfaSetup({ account, onDone }: { account: string; onDone: () => void }) {
  const [setup, setSetup] = useState<SetupData | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);

  const start = useMutation({
    mutationFn: () => api<SetupData>("/me/mfa/setup", { method: "POST" }),
    onSuccess: setSetup,
  });
  const enable = useMutation({
    mutationFn: () => api<{ recovery_codes: string[] }>("/me/mfa/enable", { method: "POST", body: { code } }),
    onSuccess: (d) => setCodes(d.recovery_codes),
  });

  if (codes) {
    return (
      <div className="grid gap-5">
        <div className="flex items-center gap-2 text-kumo-success">
          <ShieldCheckIcon size={20} weight="fill" />
          <Text bold>Two-factor authentication is on</Text>
        </div>
        <RecoveryCodes codes={codes} account={account} />
        <div>
          <Button variant="primary" onClick={onDone}>
            I have saved my codes
          </Button>
        </div>
      </div>
    );
  }

  if (!setup) {
    return (
      <div className="grid gap-4">
        <Text variant="secondary">
          Use an authenticator app such as 1Password, Google Authenticator, Microsoft Authenticator or Authy to generate one-time codes when
          you sign in.
        </Text>
        {start.error && <Banner variant="error" size="sm" description={errorMessage(start.error)} />}
        <div>
          <Button variant="primary" loading={start.isPending} onClick={() => start.mutate()}>
            Set up authenticator app
          </Button>
        </div>
      </div>
    );
  }

  return (
    <form
      className="grid gap-5"
      onSubmit={(e) => {
        e.preventDefault();
        enable.mutate();
      }}
    >
      <div className="grid gap-5 md:grid-cols-[200px_1fr]">
        <img src={setup.qr_code} alt="QR code for your authenticator app" width={200} height={200} className="rounded-lg bg-white p-2 ring ring-kumo-line" />
        <div className="grid content-start gap-3">
          <div className="grid gap-1">
            <Text bold>1. Scan the QR code</Text>
            <Text variant="secondary">Scan it with your authenticator app, or enter this key manually:</Text>
          </div>
          <ClipboardText text={setup.secret} size="sm" />
          <div className="mt-2 grid gap-1">
            <Text bold>2. Enter the 6-digit code</Text>
          </div>
          <Input
            aria-label="Verification code"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            className="w-40 font-mono tracking-normal"
            error={fieldError(enable.error, "code")}
            autoFocus
          />
        </div>
      </div>
      {enable.error && !fieldError(enable.error, "code") && <Banner variant="error" size="sm" description={errorMessage(enable.error)} />}
      <div>
        <Button type="submit" variant="primary" loading={enable.isPending} disabled={code.length !== 6}>
          Verify and enable
        </Button>
      </div>
    </form>
  );
}
