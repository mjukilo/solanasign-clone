import { useState, useEffect } from 'react';
import { encode } from 'bs58';
import { WalletConnection } from '../types/wallet';

export const useMessageSigning = (connection: WalletConnection) => {
  const [message, setMessage] = useState('');
  const [signature, setSignature] = useState('');

  useEffect(() => {
    setMessage('');
    setSignature('');
  }, [connection.publicKey, connection.providerType]);

  const signMessage = async () => {
    if (!connection.provider || !message) return;
    
    try {
      const encodedMessage = new TextEncoder().encode(message);

      if (connection.providerType === 'backpack') {
        try {
          const signedData = await connection.provider.signMessage(encodedMessage);
          console.log("Backpack signature response:", signedData);
          
          if (signedData && typeof signedData === 'object') {
            if (signedData instanceof Uint8Array) {
              setSignature(encode(signedData));
            } else if ('signature' in signedData) {
              setSignature(encode(signedData.signature));
            } else if ('data' in signedData) {
              setSignature(encode(signedData.data));
            } else {
              ['signatures', 'signed', 'signatureBytes'].some(key => {
                if (signedData[key]) {
                  setSignature(encode(signedData[key]));
                  return true;
                }
                return false;
              });
            }
          }
        } catch (error) {
          console.error("Backpack signing error:", error);
          setSignature('');
        }
      } else if (connection.providerType === 'atomic') {
        try {
          const signedData = await connection.provider.signMessage(encodedMessage);
          console.log("Atomic signature response:", signedData);
          if (signedData?.signature) {
            setSignature(encode(signedData.signature));
          }
        } catch (error) {
          console.error("Atomic signing error:", error);
          setSignature('');
        }
      } else if (connection.providerType === 'exodus') {
        try {
          const signedData = await connection.provider.signMessage(encodedMessage);
          console.log("Exodus signature response:", signedData);
          const signature = signedData?.signature || signedData;
          setSignature(encode(signature));
        } catch (error) {
          console.error("Exodus signing error:", error);
          setSignature('');
        }
      } else {
        const signedMessage = await connection.provider.signMessage(encodedMessage, "utf8");
        console.log("Standard wallet signature response:", signedMessage);
        setSignature(encode(signedMessage.signature));
      }
    } catch (error) {
      console.error("Error during signing process:", error);
      setSignature('');
    }
  };

  const copySignature = async () => {
    if (signature) {
      await navigator.clipboard.writeText(signature);
    }
  };

  return {
    message,
    signature,
    setMessage,
    signMessage,
    copySignature
  };
};
