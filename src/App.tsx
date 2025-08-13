import { useWallet } from './hooks/useWallet';
import { useMessageSigning } from './hooks/useMessageSigning';
import { SignerPanel } from './components/SignerPanel';

function App() {
  const { connection, connectWallet, disconnectWallet } = useWallet();
  const { message, signature, setMessage, signMessage, copySignature } = useMessageSigning(connection);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 flex items-center justify-center p-4">
      <SignerPanel
        connection={connection}
        message={message}
        signature={signature}
        onMessageChange={setMessage}
        onConnect={connectWallet}
        onDisconnect={disconnectWallet}
        onSign={signMessage}
        onCopySignature={copySignature}
      />
    </div>
  );
}

export default App;
