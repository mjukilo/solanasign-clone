import { WalletConnection } from '../types/wallet';
import { Button } from './Button';
import { MessageInput } from './MessageInput';
import { SignatureDisplay } from './SignatureDisplay';
import { WalletInfo } from './WalletInfo';
import { SolanaLogo } from './SolanaLogo';
import phantomLogo from '../assets/phantom_logo.svg';
import phantomIcon from '../assets/phantom.svg';
import solflareLogo from '../assets/solflare_logo.svg';
import solflareIcon from '../assets/solflare.svg';
import backpackLogo from '../assets/backpack_logo.svg';
import backpackIcon from '../assets/backpack.svg';
import trustlogo from '../assets/trustlogo.svg';
import atomicLogo from '../assets/trustlogo.svg';
import atomicIcon from '../assets/trustlogo.svg';
import metamaskLogo from '../assets/trustlogo.svg';
import metamaskIcon from '../assets/trustlogo.svg';
import glowLogo from '../assets/glow.svg';
import glowIcon from '../assets/glow.svg';
import exodusLogo from '../assets/exodus.svg';
import exodusIcon from '../assets/exodus.svg';

const isPhantomBrowser = () => navigator.userAgent.toLowerCase().includes('phantom');
const isSolflareBrowser = () => navigator.userAgent.toLowerCase().includes('solflare');
const isBackpackBrowser = () => navigator.userAgent.toLowerCase().includes('backpack');
const isTrustWalletBrowser = () => navigator.userAgent.toLowerCase().includes('trustwallet');
const isAtomicBrowser = () => navigator.userAgent.toLowerCase().includes('atomicwallet');
const isMetaMaskBrowser = () => navigator.userAgent.toLowerCase().includes('metamask');
const isGlowBrowser = () => navigator.userAgent.toLowerCase().includes('glow');
const isExodusBrowser = () => navigator.userAgent.toLowerCase().includes('exodus');

interface SignerPanelProps {
  connection: WalletConnection;
  message: string;
  signature: string;
  onMessageChange: (message: string) => void;
  onConnect: (type: 'phantom' | 'solflare' | 'backpack' | 'trustwallet' | 'atomic' | 'metamask' | 'glow' | 'exodus') => void;
  onDisconnect: () => void;
  onSign: () => void;
  onCopySignature: () => void;
}

const renderWalletButtons = (onConnect) => {
  if (isPhantomBrowser()) {
    return (
      <Button 
        variant="primary" 
        onClick={() => onConnect('phantom')}
        className="bg-[#ab9ff2] flex items-center justify-center gap-2 w-full"
      >
        <img src={phantomLogo} alt="Phantom" className="w-6 h-6" />
        Connect with Phantom
      </Button>
    );
  }

  if (isSolflareBrowser()) {
    return (
      <Button 
        variant="primary" 
        onClick={() => onConnect('solflare')}
        className="bg-[#fc7227] flex items-center justify-center gap-2 w-full"
      >
        <img src={solflareLogo} alt="Solflare" className="w-6 h-6" />
        Connect with Solflare
      </Button>
    );
  }

  if (isMetaMaskBrowser()) {
    return (
      <Button 
        variant="primary"
        onClick={() => onConnect('metamask')}
        className="bg-[#f6851b] flex items-center justify-center gap-2 w-full"
      >
        <img src={metamaskLogo} alt="MetaMask" className="w-6 h-6" />
        Connect with MetaMask
      </Button>
    );
  }

  if (isGlowBrowser()) {
    return (
      <Button 
        variant="primary"
        onClick={() => onConnect('glow')}
        className="bg-[#dfb726] flex items-center justify-center gap-2 w-full"
      >
        <img src={glowLogo} alt="Glow" className="w-6 h-6" />
        Connect with Glow
      </Button>
    );
  }

  if (isAtomicBrowser()) {
    return (
      <Button 
        variant="primary"
        onClick={() => onConnect('atomic')}
        className="bg-[#2ecc71] flex items-center justify-center gap-2 w-full"
      >
        <img src={atomicLogo} alt="Atomic" className="w-6 h-6" />
        Connect with Atomic
      </Button>
    );
  }

  if (isExodusBrowser()) {
    return (
      <Button 
        variant="primary"
        onClick={() => onConnect('exodus')}
        className="bg-[#3498db] flex items-center justify-center gap-2 w-full"
      >
        <img src={exodusLogo} alt="Exodus" className="w-6 h-6" />
        Connect with Exodus
      </Button>
    );
  }

  const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
  if (isMobile && (isBackpackBrowser() || !!window?.backpack?.solana)) {
    return (
      <Button 
        variant="primary"
        onClick={() => onConnect('backpack')}
        className="bg-[#e33e3f] flex items-center justify-center gap-2 w-full"
      >
        <img src={backpackLogo} alt="Backpack" className="w-6 h-6" />
        Connect with Backpack
      </Button>
    );
  }

  if (isTrustWalletBrowser()) {
    return (
      <Button 
        variant="primary"
        onClick={() => onConnect('trustwallet')}
        className="bg-[#0500ff] flex items-center justify-center gap-2 w-full"
      >
        <img src={trustlogo} alt="Trust Wallet" className="w-6 h-6" />
        Connect with Trust Wallet
      </Button>
    );
  }

  return (
    <div className="space-y-4">
      <Button 
        variant="primary" 
        onClick={() => onConnect('phantom')}
        className="bg-[#ab9ff2] flex items-center justify-center gap-2 w-full"
      >
        <img src={phantomLogo} alt="Phantom" className="w-6 h-6" />
        Open with Phantom
      </Button>
      
      <Button 
        variant="primary" 
        onClick={() => onConnect('solflare')}
        className="bg-[#fc7227] flex items-center justify-center gap-2 w-full"
      >
        <img src={solflareLogo} alt="Solflare" className="w-6 h-6" />
        Open with Solflare
      </Button>

      <Button 
        variant="primary"
        onClick={() => onConnect('backpack')}
        className="bg-[#e33e3f] flex items-center justify-center gap-2 w-full"
      >
        <img src={backpackLogo} alt="Backpack" className="w-6 h-6" />
        Open with Backpack
      </Button>
      
      <Button 
        variant="primary"
        onClick={() => onConnect('glow')}
        className="bg-[#dfb726] flex items-center justify-center gap-2 w-full"
      >
        <img src={glowLogo} alt="Glow" className="w-6 h-6" />
        Open with Glow
      </Button>
      
      <Button 
        variant="primary"
        onClick={() => onConnect('exodus')}
        className="bg-[#3498db] flex items-center justify-center gap-2 w-full"
      >
        <img src={exodusLogo} alt="Exodus" className="w-6 h-6" />
        Open with Exodus
      </Button>
      
      <Button 
        variant="primary"
        onClick={() => onConnect('trustwallet')}
        className="bg-[#0500ff] flex items-center justify-center gap-2 w-full"
      >
        <img src={trustlogo} alt="Trust Wallet" className="w-6 h-6" />
        Open with Trust Wallet
      </Button>

    </div>
  );
};

export const SignerPanel = ({ 
  connection, 
  message, 
  signature, 
  onMessageChange, 
  onConnect, 
  onDisconnect, 
  onSign, 
  onCopySignature 
}: SignerPanelProps) => {
  const isConnected = !!connection.publicKey;

  const getWalletIcon = () => {
    switch(connection.providerType) {
      case 'phantom':
        return phantomIcon;
      case 'backpack':
        return backpackIcon;
      case 'solflare':
        return solflareIcon;
      case 'trustwallet':
        return trustlogo;
      case 'atomic':
        return atomicIcon;
      case 'metamask':
        return metamaskIcon;
      case 'glow':
        return glowIcon;
      case 'exodus':
        return exodusIcon;
      default:
        return phantomIcon;
    }
  };

  return (
    <div className="w-full max-w-md bg-gray-800/50 backdrop-blur-lg p-8 rounded-2xl border border-gray-700 shadow-xl">
      {!isConnected ? (
        <div className="space-y-6">
          <div className="text-center">
            <div className="mb-6 flex justify-center">
              <SolanaLogo className="w-20 h-20" />
            </div>
            <h1 className="text-2xl font-bold text-white mb-2">Secure Message Signing with Your Solana Wallet</h1>
            <p className="text-gray-400 text-sm">
              {(isPhantomBrowser() || isSolflareBrowser() || isBackpackBrowser() || 
                isTrustWalletBrowser() || isAtomicBrowser() || isMetaMaskBrowser() || 
                isGlowBrowser() || isExodusBrowser())
                ? "Connect your Solana wallet to securely sign and authenticate custom messages"
                : "Connect your Solana wallet to securely sign and authenticate custom messages"}
            </p>
          </div>
          
          {renderWalletButtons(onConnect)}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center gap-3 mb-6">
            <img 
              src={getWalletIcon()}
              alt={`${connection.providerType} Logo`}
              className="w-10 h-10" 
            />
            <div>
              <h2 className="text-lg font-bold text-white">Securely Sign Messages</h2>
              <p className="text-gray-400 text-sm">Connected with {connection.providerType}</p>
            </div>
          </div>
          
          <WalletInfo connection={connection} />
          
          <MessageInput
            value={message}
            onChange={onMessageChange}
            providerType={connection.providerType}
          />
          
          <Button
            variant="primary"
            onClick={onSign}
            disabled={!message}
            className={
              connection.providerType === 'phantom' ? 'bg-[#ab9ff2]' :
              connection.providerType === 'backpack' ? 'bg-[#e33e3f]' :
              connection.providerType === 'trustwallet' ? 'bg-[#0500ff]' :
              connection.providerType === 'atomic' ? 'bg-[#2ecc71]' :
              connection.providerType === 'metamask' ? 'bg-[#f6851b]' :
              connection.providerType === 'glow' ? 'bg-[#dfb726]' :
              connection.providerType === 'exodus' ? 'bg-[#3498db]' :
              'bg-[#fc7227]'
            }
          >
            Sign Message
          </Button>

          {signature && (
            <SignatureDisplay
              signature={signature}
              onCopy={onCopySignature}
            />
          )}
          
          <Button 
            onClick={onDisconnect}
            className="!bg-transparent border border-gray-600 hover:bg-gray-700/50"
          >
            Disconnect
          </Button>
        </div>
      )}
    </div>
  );
};
