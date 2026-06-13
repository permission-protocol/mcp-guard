/**
 * Permission Deck — post a commit status back to GitHub so an approved merge's
 * check flips green automatically (closing the webhook loop). Used by the
 * onExternalApprove hook. Fail-safe: a no-op unless PP_GITHUB_TOKEN is set.
 */

export interface CommitStatus {
  state: 'success' | 'pending' | 'failure' | 'error';
  context: string;
  description?: string;
  target_url?: string;
}

export type FetchLike = (url: string, init: any) => Promise<{ ok?: boolean; status: number; text?: () => Promise<string> }>;

/** POST /repos/{repo}/statuses/{sha}. `repo` is "owner/name". Returns the HTTP status. */
export async function postCommitStatus(
  repo: string,
  sha: string,
  status: CommitStatus,
  token: string,
  fetchImpl?: FetchLike,
): Promise<{ ok: boolean; status: number }> {
  const f: FetchLike = fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const res = await f(`https://api.github.com/repos/${repo}/statuses/${sha}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
      'User-Agent': 'permission-deck',
    },
    body: JSON.stringify({
      state: status.state,
      context: status.context,
      ...(status.description ? { description: status.description.slice(0, 140) } : {}),
      ...(status.target_url ? { target_url: status.target_url } : {}),
    }),
  });
  const ok = res.ok ?? (res.status >= 200 && res.status < 300);
  return { ok, status: res.status };
}

/** The canonical "merge authorized" status for a Permission Deck receipt. */
export function authorizedStatus(approvedBy: string | null, receiptId: string, viewerUrl?: string): CommitStatus {
  return {
    state: 'success',
    context: 'Permission Deck Receipt Gate',
    description: `Authorized by ${approvedBy || 'a human'} · receipt ${receiptId}`,
    ...(viewerUrl ? { target_url: viewerUrl } : {}),
  };
}
