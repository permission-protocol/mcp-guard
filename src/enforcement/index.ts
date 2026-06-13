import { CanonicalPayload, SignedToken } from './types';
import { loadPolicy, getToolPolicy, ToolPolicy } from './policy';
import { verifyAuthorization } from './verifier';

export {
  CanonicalPayload,
  SignedToken,
  ToolPolicy,
  loadPolicy,
  getToolPolicy,
  verifyAuthorization
};

export async function interceptToolCall(
  jsonRpcMessage: any,
  publicKeyPem: string,
  expectedKeyId: string = 'pp-prod-1'
): Promise<{ allowed: boolean; reason?: string; payload?: CanonicalPayload; token?: SignedToken; policy?: ToolPolicy; policy_hash?: string }> {
  if (jsonRpcMessage.method !== 'tools/call') {
    return { allowed: true };
  }

  const toolName = jsonRpcMessage.params?.name;
  const policy = getToolPolicy(toolName);
  
  if (policy?.protected) {
    const args = jsonRpcMessage.params?.arguments || {};
    const authorization = args._authorization;
    if (!authorization) {
      return { allowed: false, reason: 'Missing _authorization block' };
    }

    const payload: CanonicalPayload = authorization.payload;
    const token: SignedToken = authorization.token;

    if (!payload || !token) {
      return { allowed: false, reason: 'Malformed authorization block' };
    }

    const { _authorization, ...executionArgs } = args;
    
    if (payload.action !== toolName) {
      return { allowed: false, reason: 'Payload action mismatch' };
    }

    if (JSON.stringify(executionArgs) !== JSON.stringify(payload.args)) {
      return { allowed: false, reason: 'Arguments mismatch' };
    }

    try {
      await verifyAuthorization(payload, token, publicKeyPem, policy, expectedKeyId);
      return { allowed: true, payload, token, policy, policy_hash: loadPolicy().policy_hash };
    } catch (err: any) {
      return { allowed: false, reason: err.message };
    }
  }

  return { allowed: true }; // Unprotected tools pass through
}
