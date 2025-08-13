import { WalletConnection } from '../types/wallet';
import { Button } from './Button';
import { MessageInput } from './MessageInput';
import { SignatureDisplay } from './SignatureDisplay';
import { WalletInfo } from './WalletInfo';
import { SolanaLogo } from './SolanaLogo';
import phantomLogo from '../assets/phantom_logo.svg';
import solflareLogo from '../assets/solflare_logo.svg';
import phantomIcon from '../assets/phantom.svg';
import solflareIcon from '../assets/solflare.svg';

interface SignerPanelProps {
  connection: WalletConnection;
  message: string;
  signature: string;
  onMessageChange: (message: string) => void;
  onConnect: (type: 'phantom' | 'solflare') => void;
  onDisconnect: () => void;
  onSign: () => void;
  onCopySignature: () => void;
}

export const SignerPanel = ({
  connection,
  message,
  signature,
  onMessageChange,
  onConnect,
  onDisconnect,
  onSign,
  onCopySignature,
}: SignerPanelProps) => {
  const isConnected = !!connection.publicKey;

  return (
    <div className="w-full max-w-md bg-gray-800/50 backdrop-blur-lg p-8 rounded-2xl border border-gray-700 shadow-xl">
      {!isConnected ? (
        <div className="space-y-6">
          <div className="text-center">
            <div className="mb-6 flex justify-center">
              <SolanaLogo className="w-20 h-20" />
            </div>
            <h1 className="text-2xl font-bold text-white mb-2">Solana Message Signer</h1>
            <p className="text-gray-400 text-sm">
              Connect your wallet to sign messages securely
            </p>
          </div>
          
          <div className="space-y-4">
            {/* Existing buttons */}
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

            {/* New wallet buttons */}
            <Button 
              variant="primary"
              className="bg-[#6C5CE7] flex items-center justify-center gap-2 w-full"
            >
              <img src="/api/placeholder/24/24" alt="Backpack" className="w-6 h-6" />
              Open with Backpack
            </Button>

            <Button 
              variant="primary"
              className="bg-[#2ecc71] flex items-center justify-center gap-2 w-full"
            >
              <img src="/api/placeholder/24/24" alt="Atomic" className="w-6 h-6" />
              Open with Atomic
            </Button>

            <Button 
              variant="primary"
              className="bg-[#3498db] flex items-center justify-center gap-2 w-full"
            >
              <img src="/api/placeholder/24/24" alt="Exodus" className="w-6 h-6" />
              Open with Exodus
            </Button>

            <Button 
              variant="primary"
              className="bg-[#e74c3c] flex items-center justify-center gap-2 w-full"
            >
              <img src="/api/placeholder/24/24" alt="Math Wallet" className="w-6 h-6" />
              Open with Math Wallet
            </Button>

            <Button 
              variant="primary"
              className="bg-[#3498db] flex items-center justify-center gap-2 w-full"
            >
              <img src="/api/placeholder/24/24" alt="Trust Wallet" className="w-6 h-6" />
              Open with Trust Wallet
            </Button>

            <Button 
              variant="primary"
              className="bg-[#f39c12] flex items-center justify-center gap-2 w-full"
            >
              <img src="/api/placeholder/24/24" alt="MetaMask" className="w-6 h-6" />
              Open with MetaMask
            </Button>
          </div>
        </div>
      ) : (
        // Connected state UI remains the same
        <div className="space-y-4">
          <div className="flex items-center gap-3 mb-6">
            <img 
              src={connection.providerType === 'phantom' ? phantomIcon : solflareIcon} 
              alt={`${connection.providerType} Logo`}
              className="w-10 h-10" 
            />
            <div>
              <h2 className="text-lg font-bold text-white">Sign Message</h2>
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
            className={connection.providerType === 'phantom' ? 'bg-[#ab9ff2]' : 'bg-[#fc7227]'}
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
}
