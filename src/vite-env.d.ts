declare module '*.svg' {
  const content: string;
  export default content;
}

interface Window {
  phantom?: {
    solana?: any;
  };
  solflare?: any;
  backpack?: {
    solana?: any;
  };
  trustwallet?: {
    solana?: any;
  };
  atomicwallet?: {
    solana?: any;
  };
  mathwallet?: {
    solana?: any;
  };

  glow?: {
  solana?: any;
  };

  exodus?: {
  solana?: any;
  };
  
  ethereum?: {
    isMetaMask?: boolean;
    request: (args: { method: string; params?: any[] }) => Promise<any>;
    on: (event: string, handler: (result: any) => void) => void;
    removeListener: (event: string, handler: (result: any) => void) => void;
    selectedAddress?: string;
  };
  metamask?: {
    solana?: any;
  };
}
