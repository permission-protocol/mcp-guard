import { v4 as uuidv4 } from 'uuid';

export interface PendingAction {
  id: string;
  timestamp: string;
  tool_name: string;
  tool_args: any;
  agent_id: string;
  rule_id: string;
  status: 'pending' | 'approved' | 'denied';
  /** The original JSON-RPC line to forward on approval */
  originalLine: string;
  /** The JSON-RPC request id for matching child responses */
  jsonrpcId: string | number | null;
  /** Resolver — call with the response line (or error JSON) to unblock the proxy */
  resolve: (responseLine: string) => void;
}

const queue: Map<string, PendingAction> = new Map();

export function addPending(
  toolName: string,
  toolArgs: any,
  agentId: string,
  ruleId: string,
  originalLine: string,
  jsonrpcId: string | number | null,
  resolve: (responseLine: string) => void,
): PendingAction {
  const action: PendingAction = {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    tool_name: toolName,
    tool_args: toolArgs,
    agent_id: agentId,
    rule_id: ruleId,
    status: 'pending',
    originalLine,
    jsonrpcId,
    resolve,
  };
  queue.set(action.id, action);
  return action;
}

export function getPending(): PendingAction[] {
  return Array.from(queue.values()).filter(a => a.status === 'pending');
}

export function getAction(id: string): PendingAction | undefined {
  return queue.get(id);
}

export function resolveAction(id: string, status: 'approved' | 'denied'): PendingAction | undefined {
  const action = queue.get(id);
  if (!action || action.status !== 'pending') return undefined;
  action.status = status;
  return action;
}

export function recentResolved(limit: number = 50): PendingAction[] {
  return Array.from(queue.values())
    .filter(a => a.status !== 'pending')
    .slice(-limit);
}
