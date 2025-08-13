import { MessageCircle } from 'lucide-react';

export const MainContent = () => {
  return (
    <div className="flex-1 p-8 flex items-center justify-center">
      <div className="max-w-md w-full text-center">
        <div className="mb-8">
          <div className="w-16 h-16 bg-purple-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <MessageCircle size={32} className="text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Solana Message Signer</h1>
          <p className="text-gray-400">
            Securely sign messages with your Solana wallet
          </p>
        </div>
      </div>
    </div>
  );
};