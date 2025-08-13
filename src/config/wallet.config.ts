import { WalletConfig } from '../types/wallet';

export const WALLET_CONFIGS: WalletConfig[] = [
  {
    id: 'phantom',
    name: 'Phantom',
    logo: '/assets/phantom_logo.svg',
    bgColor: 'bg-[#ab9ff2]',
    connectionUrl: 'https://phantom.app/ul/browse',
    downloadUrl: 'https://phantom.app/download'
  },
  {
    id: 'solflare',
    name: 'Solflare',
    logo: '/assets/solflare_logo.svg',
    bgColor: 'bg-[#fc7227]',
    connectionUrl: 'https://solflare.com/ul/v1/browse',
    downloadUrl: 'https://solflare.com/download'
  },
  {
    id: 'backpack',
    name: 'Backpack',
    logo: '/api/placeholder/24/24',
    bgColor: 'bg-[#e33e3f]',
    connectionUrl: 'https://backpack.app/connect',
    downloadUrl: 'https://www.backpack.app/'
  },
  {
    id: 'atomic',
    name: 'Atomic',
    logo: '/api/placeholder/24/24',
    bgColor: 'bg-[#2ecc71]',
    connectionUrl: 'https://atomicwallet.io/connect',
    downloadUrl: 'https://atomicwallet.io/download'
  },
  {
    id: 'exodus',
    name: 'Exodus',
    logo: '/api/placeholder/24/24',
    bgColor: 'bg-[#3498db]',
    connectionUrl: 'https://exodus.com/browser',
    downloadUrl: 'https://exodus.com/download'
  },
  {
    id: 'mathwallet',
    name: 'Math Wallet',
    logo: '/api/placeholder/24/24',
    bgColor: 'bg-[#e74c3c]',
    connectionUrl: 'https://mathwallet.org/connect',
    downloadUrl: 'https://mathwallet.org/download'
  },
  {
    id: 'trustwallet',
    name: 'Trust Wallet',
    logo: '/api/placeholder/24/24',
    bgColor: 'bg-[#3498db]',
    connectionUrl: 'https://link.trustwallet.com/connect',
    downloadUrl: 'https://trustwallet.com/download'
  },
  {
    id: 'metamask',
    name: 'MetaMask',
    logo: '/api/placeholder/24/24',
    bgColor: 'bg-[#f39c12]',
    connectionUrl: 'https://metamask.app.link/connect',
    downloadUrl: 'https://metamask.io/download/'
  }
  {
  id: 'glow',
  name: 'Glow',
  logo: '/assets/glow_logo.svg',
  bgColor: 'bg-[#FF6B6B]',
  connectionUrl: 'https://glow.app/connect',
  downloadUrl: 'https://glow.app/download'
  }
];
