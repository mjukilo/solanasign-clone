import { PublicKey } from '@solana/web3.js';

export type WalletProvider = 'phantom' | 'solflare' | 'backpack' | 'trustwallet' | 'atomic' | 'metamask' | 'glow' | 'exodus';

export interface WalletConnection {
  provider: any;
  publicKey: PublicKey | null;
  providerType: WalletProvider | null;
}

export interface MetaMaskProvider {
  isMetaMask: boolean;
  request: (args: { method: string; params?: any[] }) => Promise<any>;
  on: (event: string, handler: (result: any) => void) => void;
  removeListener: (event: string, handler: (result: any) => void) => void;
}
