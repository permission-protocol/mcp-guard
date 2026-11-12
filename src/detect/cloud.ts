/**
 * cloud_delete: delete operations on databases, volumes, disks, buckets, snapshots and
 * backups (and whole projects, resource groups and clusters that contain them) in the
 * aws, gcloud / gsutil / bq, az, doctl, flyctl, railway, supabase and kubectl CLIs.
 *
 * Matching is by the words of the command path (service, group, verb), so global options
 * may appear anywhere. A dynamic word among the first words, where the verb lives, fails
 * safe.
 *
 * Pure. No I/O.
 */
import { overShell } from './combine.js';
import { hasFlag, hasShort, type Cmd, type Word } from './shell.js';
import { found, unparseable, type DetectorResult } from './types.js';

const CLIS = new Set(['aws', 'gcloud', 'gsutil', 'bq', 'az', 'doctl', 'fly', 'flyctl', 'railway', 'supabase', 'kubectl', 'oc']);

const AWS_DELETE_OP = /^(delete|remove|terminate|purge)-[a-z0-9-]+$/;
const AWS_RESOURCE = /(db|database|cluster|volume|disk|bucket|snapshot|backup|table|file-system|vault|recovery-point|archive|replication-group|cache|keyspace|stack|instances)/;

const GCLOUD_GROUPS = new Set(['sql', 'disks', 'snapshots', 'buckets', 'backups', 'databases', 'spanner', 'bigtable', 'alloydb', 'firestore', 'filestore', 'redis', 'memcache', 'projects', 'volumes', 'instances', 'clusters', 'images', 'datasets']);
const AZ_GROUPS = new Set(['sql', 'postgres', 'mysql', 'mariadb', 'cosmosdb', 'storage', 'disk', 'snapshot', 'backup', 'group', 'redis', 'netappfiles', 'keyvault', 'aks', 'flexible-server', 'db', 'server']);
const DOCTL_GROUPS = new Set(['databases', 'database', 'db', 'dbs', 'volume', 'volumes', 'snapshot', 'snapshots', 'backups', 'backup', 'droplet', 'droplets', 'kubernetes', 'k8s', 'cluster', 'registry', 'apps']);
const FLY_GROUPS = new Set(['volumes', 'volume', 'vol', 'apps', 'app', 'postgres', 'pg', 'mpg', 'storage', 'redis', 'mysql', 'litefs', 'snapshots', 'extensions']);
const K8S_TYPES: Record<string, string> = {
  namespace: 'namespace_delete', namespaces: 'namespace_delete', ns: 'namespace_delete',
  pvc: 'volume_delete', persistentvolumeclaim: 'volume_delete', persistentvolumeclaims: 'volume_delete',
  pv: 'volume_delete', persistentvolume: 'volume_delete', persistentvolumes: 'volume_delete',
  crd: 'resource_delete', crds: 'resource_delete', customresourcedefinition: 'resource_delete', customresourcedefinitions: 'resource_delete',
};

/** Name the category of what is deleted from the words of the command path. */
function kindFor(words: string[]): string {
  const s = words.join(' ');
  if (/snapshot/.test(s)) return 'snapshot_delete';
  if (/backup|recovery-point|vault/.test(s)) return 'backup_delete';
  if (/bucket|\bs3\b|storage|\brb\b/.test(s)) return 'bucket_delete';
  if (/volume|disk|file-?system|filestore|netappfiles|\bvol\b|\bpvc?\b/.test(s)) return 'volume_delete';
  if (/\bdb\b|dbs|database|sql|table|postgres|\bpg\b|mpg|mysql|mariadb|redis|cosmosdb|spanner|bigtable|alloydb|firestore|cache|keyspace|memcache|datasets/.test(s)) return 'database_delete';
  if (/project/.test(s)) return 'project_delete';
  if (/\bgroup\b/.test(s)) return 'resource_group_delete';
  if (/cluster|kubernetes|k8s|aks/.test(s)) return 'cluster_delete';
  if (/instance|droplet/.test(s)) return 'instance_delete';
  return 'resource_delete';
}

/** Words that are not options and not option values we know of. Lower-cased. */
function pathWords(cmd: Cmd, valueFlags: Set<string> = new Set()): Word[] {
  const out: Word[] = [];
  for (let k = 0; k < cmd.args.length; k++) {
    const t = cmd.args[k].text;
    if (t.startsWith('-')) {
      if (!t.includes('=') && valueFlags.has(t)) k++;
      continue;
    }
    out.push({ ...cmd.args[k], text: t.toLowerCase() });
  }
  return out;
}

const AWS_GLOBAL = new Set(['--region', '--profile', '--output', '--endpoint-url', '--query', '--color', '--ca-bundle', '--cli-read-timeout', '--cli-connect-timeout']);
const GCLOUD_GLOBAL = new Set(['--project', '--account', '--configuration', '--format', '--verbosity', '--impersonate-service-account', '--billing-project', '--zone', '--region', '--location']);
const AZ_GLOBAL = new Set(['--subscription', '--output', '-o', '--query', '--resource-group', '-g', '--name', '-n']);
const KUBE_GLOBAL = new Set(['-n', '--namespace', '--context', '--kubeconfig', '--cluster', '--user', '-s', '--server', '-l', '--selector', '-o', '--output', '--field-selector', '--grace-period', '--timeout', '--cascade']);

function idAfter(cmd: Cmd, words: Word[], verbIdx: number): string | undefined {
  const flag = cmd.args.findIndex((w) => /^--[a-z-]*(identifier|-id|-name|bucket|instance-ids)$/.test(w.text));
  if (flag >= 0 && cmd.args[flag + 1]) return cmd.args[flag + 1].text;
  const eq = cmd.args.find((w) => /^--[a-z-]*(identifier|-id|-name|bucket)=/.test(w.text));
  if (eq) return eq.text.slice(eq.text.indexOf('=') + 1);
  return words[verbIdx + 1]?.text;
}

function check(cmd: Cmd): DetectorResult | null {
  if (!CLIS.has(cmd.name)) return null;
  const name = cmd.name;
  const valueFlags = name === 'aws' ? AWS_GLOBAL : name === 'gcloud' ? GCLOUD_GLOBAL : name === 'az' ? AZ_GLOBAL : name === 'kubectl' || name === 'oc' ? KUBE_GLOBAL : new Set<string>();
  const words = pathWords(cmd, valueFlags);
  const texts = words.map((w) => w.text);
  const recursive = hasShort(cmd.args, 'r') || hasShort(cmd.args, 'R') || hasFlag(cmd.args, '--recursive');
  const head = name === 'gcloud' || name === 'az' ? 5 : 3;
  const dynamicHead = words.slice(0, head).some((w) => w.dynamic);

  const result = ((): DetectorResult | null => {
    switch (name) {
      case 'aws': {
        if (texts.includes('s3')) {
          const i = texts.indexOf('rb');
          if (i >= 0) return found('bucket_delete', texts[i + 1]);
          const r = texts.indexOf('rm');
          if (r >= 0 && recursive) return found('bucket_delete', texts[r + 1]);
        }
        const opIdx = texts.findIndex((t) => AWS_DELETE_OP.test(t));
        if (opIdx >= 0 && AWS_RESOURCE.test(texts[opIdx])) return found(kindFor([texts[opIdx]]), idAfter(cmd, words, opIdx));
        return null;
      }
      case 'gsutil': {
        const rb = texts.indexOf('rb');
        if (rb >= 0) return found('bucket_delete', texts[rb + 1]);
        const rm = texts.indexOf('rm');
        if (rm >= 0 && (recursive || hasShort(cmd.args, 'a'))) return found('bucket_delete', texts[rm + 1]);
        return null;
      }
      case 'bq': {
        const rm = texts.indexOf('rm');
        return rm >= 0 ? found('database_delete', texts[rm + 1]) : null;
      }
      case 'gcloud': {
        const v = texts.findIndex((t) => t === 'delete' || t === 'destroy');
        if (v >= 0) {
          const groups = texts.slice(0, v);
          if (groups.some((g) => GCLOUD_GROUPS.has(g))) return found(kindFor(groups), texts[v + 1]);
        }
        const rm = texts.indexOf('rm');
        if (rm >= 0 && texts.includes('storage') && recursive) return found('bucket_delete', texts[rm + 1]);
        return null;
      }
      case 'az': {
        const v = texts.findIndex((t) => t === 'delete' || t === 'purge');
        if (v < 0) return null;
        const groups = texts.slice(0, v);
        return groups.some((g) => AZ_GROUPS.has(g)) ? found(kindFor(groups), idAfter(cmd, words, v)) : null;
      }
      case 'doctl': {
        const v = texts.findIndex((t) => t === 'delete' || t === 'd' || t === 'rm' || t === 'del');
        if (v < 0) return null;
        const groups = texts.slice(0, v);
        return groups.some((g) => DOCTL_GROUPS.has(g)) ? found(kindFor(groups), texts[v + 1]) : null;
      }
      case 'fly':
      case 'flyctl': {
        const v = texts.findIndex((t) => t === 'destroy' || t === 'delete' || t === 'rm' || t === 'remove');
        if (v < 0) return null;
        const groups = texts.slice(0, v);
        return groups.some((g) => FLY_GROUPS.has(g)) ? found(kindFor(groups), texts[v + 1]) : null;
      }
      case 'railway': {
        const v = texts.indexOf('delete');
        if (v < 0) return null;
        const kind = kindFor(texts.slice(0, v));
        return found(kind === 'resource_delete' ? 'project_delete' : kind, texts[v + 1]);
      }
      case 'supabase': {
        if (texts.includes('delete') && texts.some((t) => ['projects', 'branches', 'orgs'].includes(t))) return found(texts.includes('branches') ? 'database_delete' : 'project_delete', texts[texts.indexOf('delete') + 1]);
        if (texts[0] === 'db' && texts[1] === 'reset' && (hasFlag(cmd.args, '--linked') || hasFlag(cmd.args, '--db-url'))) return found('database_delete');
        if (texts.includes('storage') && texts.includes('rm') && recursive) return found('bucket_delete', texts[texts.indexOf('rm') + 1]);
        return null;
      }
      case 'kubectl':
      case 'oc': {
        const v = texts.indexOf('delete');
        if (v < 0) return null;
        if (hasFlag(cmd.args, '--all', '--all-namespaces', '-A')) return found('k8s_delete_all', texts[v + 1]);
        const typeWord = words[v + 1];
        if (typeWord?.dynamic) return unparseable('dynamic_argument', 'k8s_delete');
        const resources = words.slice(v + 1).filter((w) => w.text.includes('/')).map((w) => w.text.split('/')[0]);
        const types = [...(typeWord ? typeWord.text.split(',').map((t) => t.split('/')[0]) : []), ...resources];
        for (const t of types) if (K8S_TYPES[t]) return found(K8S_TYPES[t], words[v + 2]?.text ?? typeWord?.text);
        if (hasFlag(cmd.args, '-f', '--filename', '-k', '--kustomize') || cmd.args.some((w) => /^-[fk]./.test(w.text))) {
          return unparseable('dynamic_argument', 'k8s_delete');
        }
        return null;
      }
      default:
        return null;
    }
  })();
  if (result) return result;
  if (dynamicHead) return unparseable('dynamic_argument', 'cloud');
  return null;
}

export function cloudDelete(text: string): DetectorResult {
  return overShell(text, check);
}
