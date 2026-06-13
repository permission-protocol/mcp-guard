export interface CanonicalPayload {
  request_id: string;
  action: string;
  args: Record<string, any>;
  issued_at: number;
  expires_at: number;
  nonce: string;
}

export interface SignedToken {
  request_id: string;
  decision: string;
  payload_hash: string;
  signers: string[];
  roles: string[];
  signed_at: number;
  expires_at: number;
  key_id: string;
  signature: string; // Hex string
}
