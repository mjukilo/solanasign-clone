import solanaLogo from '../assets/solana-logo.svg'

interface SolanaLogoProps {
  className?: string;
}

export const SolanaLogo = ({ className = "w-16 h-16" }: SolanaLogoProps) => (
  <img src={solanaLogo} alt="Solana Logo" className={className} />
);
