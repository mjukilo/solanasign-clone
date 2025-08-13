interface MessageInputProps {
  value: string;
  onChange: (value: string) => void;
  providerType: 'phantom' | 'solflare' | null;
}

export const MessageInput = ({ value, onChange, providerType }: MessageInputProps) => {
  const focusColor = providerType === 'phantom' ? '#ab9ff2' : '#fc7227';

  return (
    <textarea
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder="Enter your message to sign..."
      className="w-full min-h-[120px] p-4 rounded-xl bg-gray-900/50 border border-gray-700 
        text-white placeholder-gray-500 text-sm resize-none outline-none
        transition-all focus:border-transparent"
      style={{
        ':focus': {
          '--tw-ring-shadow': `0 0 0 2px ${focusColor}`
        }
      } as React.CSSProperties}
    />
  );
};
