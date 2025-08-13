# 🔐 Solana Message Signer – Secure Account Ownership Verification  

## **Overview**  
Solana Message Signer is a **web application** that allows users to **sign custom messages** using their **Solana wallets** (Phantom, Solflare, Backpack, Trust Wallet, Atomic Wallet, Glow, Exodus). This signature serves as **proof of account ownership**, enabling secure authentication without passwords.  

## **Features**  
✅ **Sign custom messages** securely with supported Solana wallets  
✅ **Verify account ownership** without exposing sensitive credentials  
✅ **Wallet integration** via `@solana/wallet-adapter-react`  
✅ **Seamless user experience** with an intuitive UI  
✅ **Works on desktop & mobile** (optimized for in-app browsers)  
✅ **Lightweight & fast** thanks to Vite and Tailwind CSS  

## **How It Works**  
1. **Connect your wallet** (Phantom, Solflare, etc.).  
2. **Enter a custom message** to sign.  
3. **Sign the message** securely with your wallet.  
4. **Copy and verify** the generated signature.  

## **Tech Stack**  
🛠 **Frontend:** React (TypeScript), Vite, Tailwind CSS  
🔗 **Wallet Integration:** `@solana/wallet-adapter-react`  
🔐 **Message Signing:** Solana wallet API, `bs58` encoding  

## **Live Demo**  
🚀 **[Try it here (once deployed)](https://solanasign.io/)**  

## **Setup & Installation**  
Clone the repository:  
```bash
git clone https://github.com/your-username/solana-message-signer.git
cd solana-message-signer
```
Install dependencies:  
```bash
npm install
```
Run the development server:  
```bash
npm run dev
```
Build for production:  
```bash
npm run build
```

## **Contributing**  
Contributions are welcome! Feel free to open an issue or submit a pull request.  
