// Wallet auth via injected EIP-1193 provider (MetaMask etc). Generic: owner lane reuses as-is.
// No secrets handled here — only addresses + EIP-191 personal_sign signatures.

export function hasInjectedWallet(): boolean {
  return typeof window !== "undefined" && (window as any).ethereum != null;
}

export async function requestAccount(): Promise<string> {
  const eth = (window as any).ethereum;
  if (!eth) throw new Error("No injected wallet found. Install MetaMask or similar.");
  const accounts: string[] = await eth.request({ method: "eth_requestAccounts" });
  if (!accounts?.[0]) throw new Error("Wallet returned no accounts.");
  return accounts[0];
}

export async function personalSign(account: string, message: string): Promise<string> {
  const eth = (window as any).ethereum;
  const sig: string = await eth.request({
    method: "personal_sign",
    params: [message, account],
  });
  return sig.startsWith("0x") ? sig : `0x${sig}`;
}

/** Full login: challenge -> sign -> verify -> session wallet. Cookie set by gateway. */
export async function loginWithWallet(
  api: {
    challenge: (a: string) => Promise<{ challenge_id: string; message_to_sign: string }>;
    verify: (c: string, s: string) => Promise<{ wallet_address: string }>;
  },
): Promise<string> {
  const account = await requestAccount();
  const ch = await api.challenge(account);
  const sig = await personalSign(account, ch.message_to_sign);
  const out = await api.verify(ch.challenge_id, sig);
  return out.wallet_address;
}

// ---- Owner lane (PG-040): owner-signed PermissionRegistry transactions ----
// Selectors are keccak256 of the canonical signatures in
// packages/contracts/src/PermissionRegistry.sol:
//   registerResource(bytes32) -> ac125dd9
//   grant(bytes32,address,bytes32,uint64) -> 4c2edacb
//   revoke(bytes32,address) -> efd8871a
// No new dependency: calldata is padded manually, sent via eth_sendTransaction.
// Returned hash is PENDING until the gateway sync confirms it on-chain.

function strip0x(h: string): string {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error("expected hex value");
  return s.toLowerCase();
}

function pad32(hexNoPrefix: string): string {
  return hexNoPrefix.padStart(64, "0");
}

function encodeBytes32(h: string): string {
  const s = strip0x(h);
  if (s.length !== 64) throw new Error("expected bytes32 (0x + 64 hex)");
  return s;
}

function encodeAddress(a: string): string {
  const s = strip0x(a);
  if (s.length !== 40) throw new Error("expected address (0x + 40 hex)");
  return pad32(s);
}

function encodeUint64(n: number): string {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error("uint64 out of range");
  return pad32(n.toString(16));
}

async function sendTx(from: string, to: string, data: string): Promise<string> {
  const eth = (window as any).ethereum;
  const hash: string = await eth.request({
    method: "eth_sendTransaction",
    params: [{ from, to, data }],
  });
  return hash;
}

export async function sendRegisterTx(contract: string, resourceId: string): Promise<string> {
  const from = await requestAccount();
  return sendTx(from, contract, `0xac125dd9${encodeBytes32(resourceId)}`);
}

export async function sendGrantTx(
  contract: string,
  resourceId: string,
  reader: string,
  policyDigest: string,
  expiresAt: number,
): Promise<string> {
  const from = await requestAccount();
  const data =
    `0x4c2edacb${encodeBytes32(resourceId)}${encodeAddress(reader)}` +
    `${encodeBytes32(policyDigest)}${encodeUint64(expiresAt)}`;
  return sendTx(from, contract, data);
}

export async function sendRevokeTx(
  contract: string,
  resourceId: string,
  reader: string,
): Promise<string> {
  const from = await requestAccount();
  return sendTx(from, contract, `0xefd8871a${encodeBytes32(resourceId)}${encodeAddress(reader)}`);
}

export function defaultContractAddress(): string {
  return (process.env.NEXT_PUBLIC_CONTRACT_ADDRESS ?? "") as string;
}

export function defaultChainId(): number {
  return Number(process.env.NEXT_PUBLIC_CHAIN_ID ?? 31337);
}

// Verb-style aliases used by login/owner pages (same behavior, same wallet).
export const hasWallet = hasInjectedWallet;
export const connectWallet = requestAccount;
export async function signLoginMessage(message: string): Promise<string> {
  const account = await requestAccount();
  return personalSign(account, message);
}
