import { WalletConnection } from '../types/wallet';

interface WalletInfoProps {
  connection: WalletConnection;
}

export const WalletInfo = ({ connection }: WalletInfoProps) => {
  return (
    <div className="bg-gray-900/50 p-4 rounded-xl border border-gray-700">
      <div className="text-gray-400 text-sm mb-1">Wallet Address</div>
      <div className="text-sm font-mono text-white break-all">
        {connection.publicKey?.toBase58()}
      </div>
    </div>
  );
};