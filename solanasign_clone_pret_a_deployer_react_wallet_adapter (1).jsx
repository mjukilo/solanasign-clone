import React, { useCallback, useEffect, useMemo, useState } from "react";
import { ConnectionProvider, WalletProvider, useWallet } from "@solana/wallet-adapter-react";
import { WalletModalProvider, WalletMultiButton } from "@solana/wallet-adapter-react-ui";
import { BackpackWalletAdapter } from "@solana/wallet-adapter-backpack";
import { PhantomWalletAdapter } from "@solana/wallet-adapter-phantom";
import { SolflareWalletAdapter } from "@solana/wallet-adapter-solflare";
import "@solana/wallet-adapter-react-ui/styles.css";

/**
 * SolanaSign – Clone prêt à déployer (v3) – 
 * Fix: évite l'erreur "TypeError: Cannot read properties of null (reading 'v4')"
 *
 * 👉 Problème probable: imports de libs externes (p.ex. `tweetnacl`, `bs58`) qui,
 *    selon l'environnement sandbox, injectent des dépendances (uuid/crypto) non dispo.
 *
 * ✅ Correction:
 *  - Retrait des imports `tweetnacl` et `bs58` (sources fréquentes de collisions bundler)
 *  - Implémentations **maison** de base58 (Bitcoin alphabet) en pur JS
 *  - Vérification Ed25519 via **WebCrypto** (`crypto.subtle`) si disponible, sinon désactivée
 *  - Aucune dépendance à `uuid`/`clusterApiUrl`/`web3 crypto`
 *  - Tests intégrés mis à jour (sans libs externes) + nouveaux cas
 *
 * NOTE: la signature reste off‑chain via Wallet Adapter (`signMessage`).
 */

// ---------------------------
// Helpers UI
// ---------------------------
function cn(...c: Array<string | false | null | undefined>) {
  return c.filter(Boolean).join(" ");
}

function useNowIso() {
  const [now, setNow] = useState<string>(new Date().toISOString());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date().toISOString()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

// ---------------------------
// Crypto helpers (no external deps)
// ---------------------------
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  for (let i = 0; i < B58_ALPHABET.length; i++) m[B58_ALPHABET[i]] = i;
  return m;
})();

function b58encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let out = "";
  while (n > 0n) {
    const rem = Number(n % 58n);
    n = n / 58n;
    out = B58_ALPHABET[rem] + out;
  }
  // leading zeros → '1'
  let zeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) zeros++;
  return "1".repeat(zeros) + (out || "");
}

function b58decode(s: string): Uint8Array {
  let n = 0n;
  for (let i = 0; i < s.length; i++) {
    const v = B58_MAP[s[i]];
    if (v === undefined) throw new Error("Invalid base58 character: " + s[i]);
    n = n * 58n + BigInt(v);
  }
  const out: number[] = [];
  while (n > 0n) {
    out.push(Number(n % 256n));
    n = n / 256n;
  }
  out.reverse();
  // leading '1' → 0x00
  let ones = 0;
  for (let i = 0; i < s.length && s[i] === "1"; i++) ones++;
  return new Uint8Array([...Array(ones).fill(0), ...out]);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomNonce(len = 24): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  try {
    const arr = new Uint8Array(len);
    (globalThis.crypto || (globalThis as any).msCrypto).getRandomValues(arr);
    for (let i = 0; i < len; i++) out += alphabet[arr[i] % alphabet.length];
  } catch {
    for (let i = 0; i < len; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

// WebCrypto Ed25519 helpers
async function ed25519VerifyWebCrypto(pubkeyRaw32: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (!(globalThis.crypto && (globalThis.crypto as any).subtle)) return false;
  try {
    const spki = ed25519RawToSpki(pubkeyRaw32);
    const key = await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
  } catch {
    return false;
  }
}

function ed25519RawToSpki(pubkeyRaw32: Uint8Array): ArrayBuffer {
  if (pubkeyRaw32.length !== 32) throw new Error("Invalid Ed25519 public key length");
  // DER prefix for Ed25519 SPKI: 30 2A 30 05 06 03 2B 65 70 03 21 00
  const prefix = Uint8Array.from([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00]);
  const spki = new Uint8Array(prefix.length + 32);
  spki.set(prefix, 0);
  spki.set(pubkeyRaw32, prefix.length);
  return spki.buffer;
}

// ---------------------------
// Déploiement – blocs à copier (sans backticks)
// ---------------------------
const PACKAGE_JSON_TEXT = `{
  "name": "solanasign-clone",
  "version": "1.0.0",
  "private": true,
  "homepage": "https://<ton-user>.github.io/<ton-repo>",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "deploy": "vite build && gh-pages -d dist"
  },
  "dependencies": {
    "@solana/wallet-adapter-backpack": "^0.1.5",
    "@solana/wallet-adapter-phantom": "^0.9.23",
    "@solana/wallet-adapter-react": "^0.15.26",
    "@solana/wallet-adapter-react-ui": "^0.9.26",
    "@solana/wallet-adapter-solflare": "^0.9.23",
    "@solana/web3.js": "^1.95.3",
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  },
  "devDependencies": {
    "@types/react": "^18.0.37",
    "@types/react-dom": "^18.0.11",
    "@vitejs/plugin-react": "^4.0.0",
    "gh-pages": "^6.1.1",
    "typescript": "^5.1.3",
    "vite": "^4.4.9"
  }
}`;

const VITE_CONFIG_TEXT = `import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({ plugins: [react()], base: '/<ton-repo>/' });`;

function CopyBlock({ title, text }: { title: string; text: string }) {
  const onCopy = useCallback(() => { navigator.clipboard.writeText(text).catch(() => {}); }, [text]);
  return (
    <div className="rounded-2xl border border-neutral-200 dark:border-neutral-800 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-neutral-100 dark:bg-neutral-900">
        <div className="text-sm font-medium">{title}</div>
        <button onClick={onCopy} className="text-xs border px-2 py-1 rounded">Copy</button>
      </div>
      <pre className="p-4 text-xs overflow-auto whitespace-pre-wrap">{text}</pre>
    </div>
  );
}

// ---------------------------
// App – signature off‑chain
// ---------------------------
function AppInner() {
  const { publicKey, signMessage } = useWallet();
  const [message, setMessage] = useState<string>("Hello from solanasign clone – change me!");
  const [signatureBytes, setSignatureBytes] = useState<Uint8Array | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [verifySupported, setVerifySupported] = useState<boolean>(false);

  const domain = typeof window !== "undefined" ? window.location.hostname : "localhost";
  const nowIso = useNowIso();

  useEffect(() => {
    setVerifySupported(Boolean(globalThis.crypto && (globalThis.crypto as any).subtle));
  }, []);

  const buildStructuredMessage = useCallback(() => {
    const addr = publicKey?.toBase58() || "<WALLET_NOT_CONNECTED>";
    const issuedAt = new Date().toISOString();
    const expirationTime = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const nonce = randomNonce(24);
    const template = `Sign-In With Solana\nDomain: ${domain}\nAddress: ${addr}\nStatement: Sign this message to prove you own this wallet. No blockchain transaction will occur.\nURI: https://${domain}\nVersion: 1\nNonce: ${nonce}\nIssued At: ${issuedAt}\nExpiration Time: ${expirationTime}`;
    setMessage(template);
    setSignatureBytes(null);
    setVerified(null);
  }, [publicKey, domain]);

  const onSign = useCallback(async () => {
    if (!signMessage) { alert("Votre wallet ne supporte pas signMessage."); return; }
    try {
      setBusy(true); setVerified(null); setSignatureBytes(null);
      const encoded = new TextEncoder().encode(message);
      const sig = await signMessage(encoded);
      setSignatureBytes(sig);
    } catch (e: any) {
      console.error(e); alert(e?.message || "Signature annulée ou échouée.");
    } finally { setBusy(false); }
  }, [message, signMessage]);

  const onVerify = useCallback(async () => {
    if (!signatureBytes || !publicKey) return;
    const encoded = new TextEncoder().encode(message);
    const ok = await ed25519VerifyWebCrypto(publicKey.toBytes(), encoded, signatureBytes);
    setVerified(ok);
  }, [message, signatureBytes, publicKey]);

  const onDownload = useCallback(() => {
    const data = {
      domain,
      message,
      publicKey: publicKey?.toBase58() || null,
      signature_base58: signatureBytes ? b58encode(signatureBytes) : null,
      signature_hex: signatureBytes ? toHex(signatureBytes) : null,
      issuedAt: nowIso,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `solanasign-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  }, [domain, message, publicKey, signatureBytes, nowIso]);

  const pubkey58 = useMemo(() => publicKey?.toBase58() || "—", [publicKey]);
  const sig58 = useMemo(() => (signatureBytes ? b58encode(signatureBytes) : "—"), [signatureBytes]);
  const sigHex = useMemo(() => (signatureBytes ? toHex(signatureBytes) : "—"), [signatureBytes]);

  return (
    <div className="min-h-screen w-full bg-gradient-to-b from-neutral-50 to-neutral-100 dark:from-neutral-950 dark:to-neutral-900 text-neutral-900 dark:text-neutral-100">
      <div className="max-w-3xl mx-auto p-6 pb-24 space-y-6">
        <header className="flex items-center justify-between py-4">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-2xl bg-black/90 dark:bg-white/90 flex items-center justify-center text-white dark:text-black font-bold">S</div>
            <div>
              <h1 className="text-2xl font-bold">SolanaSign – Clone</h1>
              <p className="text-sm opacity-70">Signer des messages off‑chain avec votre wallet Solana</p>
            </div>
          </div>
          <WalletMultiButton className="!rounded-2xl !px-4 !py-2" />
        </header>

        {/* Assistant déploiement */}
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Assistant déploiement (GitHub Pages)</h2>
          <p className="text-sm opacity-80">Copiez ces fichiers <strong>sans backticks</strong> dans votre projet Vite.</p>
          <CopyBlock title="package.json" text={PACKAGE_JSON_TEXT} />
          <CopyBlock title="vite.config.ts" text={VITE_CONFIG_TEXT} />
        </section>

        {/* Message */}
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Message à signer</h2>
          <div className="flex items-center justify-between text-sm">
            <span className="opacity-70">Domaine détecté :</span>
            <code className="px-2 py-1 rounded bg-neutral-100 dark:bg-neutral-800">{typeof window!=="undefined"?window.location.hostname:"localhost"}</code>
          </div>
          <textarea
            value={message}
            onChange={(e) => { setMessage(e.target.value); setSignatureBytes(null); setVerified(null); }}
            rows={8}
            className="w-full resize-y rounded-2xl border border-neutral-300 dark:border-neutral-700 bg-white/80 dark:bg-neutral-900/80 p-4 focus:outline-none focus:ring-2 focus:ring-black/20 dark:focus:ring-white/20"
            placeholder="Écrivez le message à signer..."
          />
          <div className="flex flex-wrap gap-2">
            <button onClick={buildStructuredMessage} className="px-3 py-2 rounded-xl bg-neutral-900 text-white dark:bg-white dark:text-black hover:opacity-90">Pré-remplir (SIWS‑like)</button>
            <button onClick={() => { setMessage(""); setSignatureBytes(null); setVerified(null); }} className="px-3 py-2 rounded-xl border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-50 dark:hover:bg-neutral-800">Vider</button>
          </div>
        </section>

        {/* Signature */}
        <section className="space-y-4">
          <h2 className="text-lg font-semibold">Signature</h2>
          <div className="flex items-center justify-between">
            <div className="text-sm opacity-80">Adresse (Base58)</div>
            <code className="text-xs px-2 py-1 rounded bg-neutral-100 dark:bg-neutral-800 break-all">{pubkey58}</code>
          </div>
          <div className="flex gap-2">
            <button onClick={onSign} disabled={!publicKey || !signMessage || busy || !message} className={cn("px-4 py-2 rounded-xl bg-neutral-900 text-white dark:bg-white dark:text-black", (!publicKey || !signMessage || busy || !message) && "opacity-50 cursor-not-allowed")}>{busy ? "Signature..." : "Signer le message"}</button>
            <button onClick={onVerify} disabled={!signatureBytes || !publicKey || !verifySupported} className={cn("px-4 py-2 rounded-xl border border-neutral-300 dark:border-neutral-700", (!signatureBytes || !publicKey || !verifySupported) && "opacity-50 cursor-not-allowed")}>Vérifier (WebCrypto)</button>
            <button onClick={onDownload} disabled={!signatureBytes} className={cn("px-4 py-2 rounded-xl border border-neutral-300 dark:border-neutral-700", !signatureBytes && "opacity-50 cursor-not-allowed")}>Télécharger JSON</button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <KV label="Signature (Base58)" value={sig58} canCopy={!!signatureBytes} />
            <KV label="Signature (Hex)" value={sigHex} canCopy={!!signatureBytes} />
          </div>
          {verified !== null && (
            <div className={cn("p-3 rounded-xl border text-sm", verified ? "border-green-300 bg-green-50 text-green-900 dark:border-green-700 dark:bg-green-950/40 dark:text-green-200" : "border-red-300 bg-red-50 text-red-900 dark:border-red-700 dark:bg-red-950/40 dark:text-red-200")}>{verified ? "Signature vérifiée ✅" : "Échec de vérification ❌"}</div>
          )}
          {!verifySupported && (
            <div className="p-3 rounded-xl border border-amber-300 bg-amber-50 text-amber-900 text-sm dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-200">Vérification WebCrypto non disponible dans cet environnement. La signature reste valide, mais non vérifiée localement.</div>
          )}
          <p className="text-xs opacity-70">* La signature est <strong>off‑chain</strong> (aucun frais).</p>
        </section>

        {/* Tests intégrés */}
        <section className="space-y-2">
          <h2 className="text-lg font-semibold">Tests intégrés</h2>
          <SelfTests />
        </section>

        <footer className="pt-6 text-center text-xs opacity-60">{"Dernière mise à jour " + nowIso}</footer>
      </div>
    </div>
  );
}

function KV({ label, value, canCopy }: { label: string; value: string; canCopy?: boolean }) {
  const onCopy = useCallback(() => { if (canCopy) navigator.clipboard.writeText(value).catch(() => {}); }, [value, canCopy]);
  return (
    <div className="p-4 rounded-xl bg-neutral-50 dark:bg-neutral-800/60 border border-neutral-200 dark:border-neutral-700">
      <div className="flex items-center justify-between text-sm mb-2">
        <span className="opacity-70">{label}</span>
        <button onClick={onCopy} disabled={!canCopy} className={cn("text-xs px-2 py-1 rounded border border-neutral-300 dark:border-neutral-600", !canCopy && "opacity-50 cursor-not-allowed")}>Copy</button>
      </div>
      <code className="text-xs break-all block">{value || "—"}</code>
    </div>
  );
}

// ---------------------------
// Tests (sans libs externes)
// ---------------------------
function TestRow({ label, ok, details }: { label: string; ok: boolean; details?: string }) {
  return (
    <div className={cn("flex items-start justify-between gap-4 p-3 rounded-xl border text-sm", ok ? "border-green-300 bg-green-50 text-green-900 dark:border-green-700 dark:bg-green-950/40 dark:text-green-200" : "border-red-300 bg-red-50 text-red-900 dark:border-red-700 dark:bg-red-950/40 dark:text-red-200")}> 
      <div className="font-medium">{label}</div>
      <div className="opacity-70 text-xs max-w-[60%] break-words">{details}</div>
      <div className={cn("ml-auto text-xs px-2 py-1 rounded", ok ? "bg-green-600 text-white" : "bg-red-600 text-white")}>{ok ? "OK" : "FAIL"}</div>
    </div>
  );
}

function SelfTests() {
  const [rows, setRows] = useState<Array<{ label: string; ok: boolean; details?: string }>>([]);

  useEffect(() => {
    const r: Array<{ label: string; ok: boolean; details?: string }> = [];

    // 1) randomNonce longueur & diversité
    const a = randomNonce(24), b = randomNonce(24);
    r.push({ label: "randomNonce longueur 24", ok: a.length === 24, details: a });
    r.push({ label: "randomNonce diversité", ok: a !== b, details: `${a} vs ${b}` });

    // 2) toHex conversion
    const bytes = new Uint8Array([0, 1, 2, 254, 255]);
    const hx = toHex(bytes);
    r.push({ label: "toHex conversion", ok: hx === "000102feff", details: hx });

    // 3) base58 enc/dec roundtrip
    const msg = new TextEncoder().encode("test");
    const enc = b58encode(msg);
    const dec = b58decode(enc);
    const okB58 = dec.length === msg.length && dec.every((v, i) => v === msg[i]);
    r.push({ label: "base58 roundtrip", ok: okB58, details: enc });

    // 4) base58 vecteur connu
    r.push({ label: "base58('test') == 3yZe7d", ok: enc === "3yZe7d", details: enc });

    // 5) SPKI Ed25519 length
    const dummy = new Uint8Array(32); // zeros
    const spki = ed25519RawToSpki(dummy);
    r.push({ label: "SPKI length == 44", ok: (spki.byteLength === 44), details: String(spki.byteLength) });

    // 6) WebCrypto support flag
    const wc = Boolean(globalThis.crypto && (globalThis.crypto as any).subtle);
    r.push({ label: "WebCrypto.subtle présent", ok: wc, details: wc ? "yes" : "no" });

    setRows(r);
  }, []);

  return (
    <div className="space-y-2">
      {rows.map((t, i) => <TestRow key={i} label={t.label} ok={t.ok} details={t.details} />)}
      {rows.length === 0 && <div className="text-sm opacity-70">Exécution des tests…</div>}
    </div>
  );
}

// ---------------------------
// Providers (wallets + endpoint explicite)
// ---------------------------
function Providers({ children }: { children: React.ReactNode }) {
  const ENDPOINT = "https://api.mainnet-beta.solana.com"; // pas de clusterApiUrl
  const wallets = useMemo(
    () => [new PhantomWalletAdapter(), new SolflareWalletAdapter(), new BackpackWalletAdapter()],
    []
  );
  return (
    <ConnectionProvider endpoint={ENDPOINT}>
      <WalletProvider wallets={wallets} autoConnect>
        <WalletModalProvider>{children}</WalletModalProvider>
      </WalletProvider>
    </ConnectionProvider>
  );
}

export default function SolanaSignClone() {
  return (
    <Providers>
      <AppInner />
    </Providers>
  );
}
