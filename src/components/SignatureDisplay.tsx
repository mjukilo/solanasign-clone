import { Copy, CheckCircle2 } from 'lucide-react';
import { useState } from 'react';

interface SignatureDisplayProps {
  signature: string;
  onCopy: () => void;
}

export const SignatureDisplay = ({ signature, onCopy }: SignatureDisplayProps) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    onCopy();
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      onClick={handleCopy}
      className="bg-gray-900/50 p-4 rounded-xl border border-gray-700 break-all 
        text-sm text-gray-300 cursor-pointer group relative hover:border-gray-600 transition-all"
    >
      <div className="absolute right-3 top-3 text-gray-400 group-hover:text-white transition-colors">
        {copied ? <CheckCircle2 size={16} className="text-green-500" /> : <Copy size={16} />}
      </div>
      {signature}
      <div className="text-xs mt-2 text-gray-500">Click to copy signature</div>
    </div>
  );
};