#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { chooseAppSecretStorage, prepareAppSecretStorage, storagePreview } from './app-secret-storage.ts';
import { join } from 'node:path';
import { findProject, resolveProjectContext, writeProject, PROJECT_FILE, type ProjectContext } from './project.ts';
import { Command, CommanderError } from 'commander';
import { DashboardClient, tokenClaims } from './client.ts';
import { browserLogin } from './browser.ts';
import { emailLogin, validateEmail } from './login.ts';
import { browserLauncherAvailable, requireInteractiveLogin, openDefaultBrowser } from './terminal.ts';
import { CliError, redact } from './errors.ts';
import { KeychainStore, ProfileStore, validateId, validateSecretRef, type ProfileConfig, type SecretRef } from './store.ts';
import { ResourceSecretStore, runWithSecret, sameSecretRef, validateSecretCommand } from './secrets.ts';
import { operations, operationSchema, type JsonObject, type OperationInput } from './operations.ts';
import { readBody, readQuery, optionFlag } from './input.ts';
import { downloadToFile } from './output.ts';
import { readImage, imageInfo, parseImageReceipt } from './image-operations.ts';
import { guideIndex, guidePath, readGuide, searchGuides, commandGuides, guideRefs, localExamples } from './docs.ts';

const version = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const program = new Command().name('privy')
  .description('Unofficial Privy management CLI. JSON on stdout; errors/progress on stderr.\nStart: privy cli search "your task" → privy schema <command>.\nWorkflow guides: privy docs (local, version-matched; no login needed).')
  .version(version)
  .option('--profile <name>', 'credential/config profile (otherwise PRIVY_PROFILE, project binding, then default)', 'default')
  .option('--app <id>', 'app ID (overrides matching project binding and profile selection)')
  .option('--account <id>', 'account/team ID for account-scoped operations')
  .option('--no-project', 'ignore privy.json directory context; profile protection still applies')
  .option('--json', 'JSON output (already the default)')
  .configureOutput({ writeErr: () => {} }).exitOverride();
const output = (value: unknown) => console.log(JSON.stringify(redact(value), null, 2));
const log = (value: string) => console.error(value);
const interrupted = new AbortController();
process.once('SIGINT', () => interrupted.abort());
process.once('SIGTERM', () => interrupted.abort());

async function run(command: Command, fn: (context: {
  client: DashboardClient; profiles: ProfileStore; credentials: KeychainStore;
  config: Awaited<ReturnType<ProfileStore['load']>>; options: JsonObject;
  project: ProjectContext | undefined; context: ReturnType<typeof resolveProjectContext>;
}) => Promise<unknown>) {
  const options = command.optsWithGlobals();
  const project = options.project === false ? undefined : await findProject();
  const context = resolveProjectContext({ project, explicitApp: options.app,
    explicitProfile: command.getOptionValueSourceWithGlobals('profile') === 'cli' ? options.profile : undefined,
    environmentProfile: process.env.PRIVY_PROFILE || undefined });
  options.profile = context.profile;
  options.app = context.appId;
  const profiles = new ProfileStore(options.profile);
  const credentials = new KeychainStore(options.profile);
  return profiles.locked(async () => {
    const config = await profiles.load();
    const client = new DashboardClient(credentials, config, undefined, interrupted.signal);
    const value = await fn({ client, profiles, credentials, config, options, project, context });
    if (value !== undefined) output(value);
  });
}
function requireYes(options: JsonObject): void {
  if (!options.yes) throw new CliError('CONFIRMATION_REQUIRED', 'Mutation requires --yes. Use --dry-run for an offline request preview first.', 2);
}

async function persistResourceSecret(profiles: ProfileStore, config: ProfileConfig, profile: string, ref: SecretRef, value: string) {
  await new ResourceSecretStore(profile).save(ref, value);
  const refs = [...(config.secretRefs ?? []).filter(r => !sameSecretRef(r, ref)), ref];
  try { await profiles.save({ ...config, secretRefs: refs }); config.secretRefs = refs; }
  catch { throw new CliError('SECRET_INDEX_FAILED', `Secret is stored in the OS credential store, but its nonsecret index could not be updated. Inspect secrets status ${ref.kind} ${ref.id} --app ${ref.appId}; do not repeat a remote mutation.`); }
  return { reference: ref, stored: true, verified: true, storage: 'OS credential store', valuePrinted: false };
}

const groupDescriptions: Record<string, string> = {
  auth: 'Dashboard authentication and profiles', apps: 'Application management',
  'apps config': 'Inspect, preview and update app configuration', config: 'App configuration workflows; get/update also alias apps config',
  approvals: 'Proposal metadata and human dashboard review (no automatic authorization)',
  integrations: 'Provider configuration and safe credential metadata; not purchases or transactions',
  'global-wallet': 'Cross-app wallet settings, connection permissions and hosted logo files',
  'global-wallet providers': 'Explicit consumer-side provider connections and access requests',
  'global-wallet requesters': 'Provider-side connection metadata and deliberately acknowledged access changes',
  'config smart-wallets': 'Smart-wallet provider/chain configuration; no deployments, signing or funding',
  secrets: 'Local app-scoped OS credential storage; values are never printed by the CLI',
  webhooks: 'Endpoint configuration, safe key storage and delivery inspection',
  credentials: 'App API secrets: choose env file, Keychain, both or neither; explicit revocation',
  domains: 'HTTP-only cookie domain/DNS configuration, not the allowed-origin list',
  providers: 'App login provider configuration; distinct from enabling login',
  access: 'App-user allow/deny lists and access controls',
  accounts: 'Dashboard accounts', users: 'User inspection, provisioning and access management', 'users imports': 'Bulk user import jobs', clients: 'Application clients',
  wallets: 'Wallet inspection, provisioning and control configuration', transactions: 'Read-only transaction and action history',
  organizations: 'App-scoped user organizations', 'wallets exports': 'Wallet CSV export jobs (not private keys)', policies: 'Inspect and manage unowned authorization policies',
  'policies rules': 'Inspect and manage policy rules; no wallet actions are executed',
  'key-quorums': 'Authorization key quorums', keys: 'Compatibility alias for key-quorums',
  analytics: 'App analytics', cli: 'Local discovery for agents and developers', project: 'Bind a directory to a CLI profile and app (local only)',
};
function group(path: string): Command {
  let parent = program, prefix = '';
  for (const part of path.split(' ').filter(Boolean)) {
    prefix = [prefix, part].filter(Boolean).join(' ');
    const existing = parent.commands.find(c => c.name() === part);
    if (existing) parent = existing;
    else {
      const created = parent.command(part).description(groupDescriptions[prefix] || prefix);
      created.action(() => created.outputHelp());
      parent = created;
    }
  }
  return parent;
}

// Generated resource surface: definition -> help/flags -> validated plan -> execution.
for (const op of operations) {
  for (const path of [op.command, ...(op.aliases ?? [])]) {
    const parts = path.split(' '), verb = parts.pop()!;
    const command = group(parts.join(' ')).command(verb).description(op.summary)
      .option('--dry-run', 'validate and print the API request without network access or credentials');
    if (op.imageAction === 'upload') command.argument('<image-file>', 'public-safe PNG/JPEG/WebP file; original bytes/metadata are sent to public image hosting').option('--stage-only', 'upload and check readiness, but leave current logo unchanged; retain checkpoint for explicit finalize');
    for (const param of op.params ?? []) command.argument(`<${param.replaceAll('_', '-')}>`, op.ecosystemConnection ? 'counterpart app ID from the selected app’s connection list; both app IDs are protected' : `${param.replaceAll('_', ' ')} within the selected app`);
    for (const [key, field] of Object.entries(op.query ?? {}).filter(([key]) => !op.queryFromParams?.[key])) command.option(`--${optionFlag(key)} <${field.type}>`, field.description);
    if (op.jwtAction && op.jwtAction !== 'read' || op.securitySetting && op.securitySetting.action !== 'read' || op.availabilityAction === 'update' || op.advancedAction === 'merging-update' || op.advancedAction === 'captcha-update') command.option('--allow-access-change', 'acknowledge cross-app access or customer authentication impact').option('--confirm-name <name>', 'exact selected app name, verified against fresh state');
    if (op.securitySetting?.action === 'rotate') command.option('--allow-session-impact', 'acknowledge key-consumer updates and session invalidation risk; rotates once only');
    if (op.jwtAction === 'configure') command.option('--enable-auth', 'explicitly allow initial app enablement before verifier configuration; two non-atomic writes').option('--allow-unrestricted-jwt', 'acknowledge disabling the audience/additional-claim requirement; Firebase still requires audience');
    if (op.ecosystemConnection) {
      if (op.ecosystemConnection.action === 'list') command.option('--all', 'show all returned connection metadata, capped at 1000; no extra requests or invented pagination');
      else command.option('--allow-access-change', 'acknowledge cross-app grants/revocations or an external access request; approval can have irreversible effects');
    }
    if (op.pagination) command.option('--all', 'follow cursors, bounded by --max-pages')
      .option('--max-pages <number>', 'maximum pages with --all (1–100; default 10)');
    if (op.method !== 'GET') command.option('--yes', 'confirm this mutation or export');
    if (op.behavior === 'create-app' || op.credentialWrite === 'create') command
      .option('--secret-store <destination>', 'app API secret destination: env, keychain, both or none; required non-interactively')
      .option('--env-output <path>', 'server env file for env/both; preserve other variables; write with mode 0600')
      .option('--env-key <name>', 'server-only env variable (default PRIVY_APP_SECRET)')
      .option('--overwrite-env', 'explicitly allow replacing the target variable in an existing env file');
    if (op.download) command.option('--output <path>', 'new private output file; never overwrites an existing path');
    if (op.browserHandoff) command.option('--no-open', 'print the human-review URL without opening the browser');
    if (op.accountView && op.accountView !== 'get') command.option('--include-identities', 'explicitly include member/invitation identities; potentially sensitive');
    if (op.accountJwtFeature === 'update') command.option('--confirm-account <name>', 'exact workspace name; affects every app in this account').option('--allow-access-change', 'acknowledge account-wide third-party authentication capability change');
    if (op.accountWrite) command.option('--confirm-account <name>', 'exact account name; this is an account-wide mutation').option('--allow-self-impact', 'explicitly acknowledge changing/removing your own membership; last-admin guard still applies');
    if (op.publicWallet === 'archive') command.option('--confirm-wallet <id>', 'exact wallet ID; archive stops writes/signing and has no CLI restoration');
    if (op.publicUserMetadata || op.publicWallet || op.publicOrganizationDelete) command.option('--credential <id>', 'app API credential ID in this app/profile OS vault; writes require full access');
    if (op.domainWrite) command.option('--allow-session-impact', 'acknowledge that disabling/deleting cookie domains can log out app users');
    if (op.domainWrite === 'delete') command.option('--confirm-domain <hostname>', 'confirm the current cookie domain before removing it');
    if (op.confirmUrl) command.option('--confirm-url <url>', 'confirm the exact current HTTPS receiver URL before deletion or notification actions');
    if (op.body?.properties.owner_id) command.option('--confirm-owner <id>', 'explicitly confirm assigning this owner; later control changes require owner authorization');
    if (op.behavior === 'delete-app' || op.policyWrite === 'delete' || op.publicOrganizationDelete) command.option('--confirm-name <name>', 'exact resource name, checked against a fresh preflight read');
    if (op.body && !op.generatedBody) {
      command.option('--body <json>', 'JSON body, or - to read stdin')
        .option('--file <path>', 'JSON body file, or - to read stdin');
      for (const [key, field] of Object.entries(op.body.properties).filter(([key]) => !op.bodyFromParams?.[key] && !op.body!.properties[key].sensitive)) {
        command.option(`--${optionFlag(key)} <${field.type === 'array' ? 'json' : field.type}>`, field.description);
      }
    }
    if (op.id === 'config.get' || op.id === 'apps.get') command.option('--field <name>', 'return one top-level configuration field');
    if (op.behavior === 'update-app') command.option('--patch <json>', 'compatibility alias for --body');
    if (op.behavior === 'update-app' || op.userWrite === 'update' || op.walletWrite === 'update' || op.organizationWrite === 'update' || op.appClientWrite === 'update' || op.domainWrite === 'configure' || op.settingsWrite || op.publicUserMetadata || op.providerWrite === 'update' || op.telegram === 'update' || op.integration?.action === 'update' || op.availabilityAction === 'update' || op.advancedAction === 'merging-update' || op.advancedAction === 'captcha-update' || op.securitySetting?.action === 'update' || op.jwtAction === 'configure' || op.accountJwtFeature === 'update' || op.webhookWrite === 'subscriptions' || op.webhookWrite === 'watchlist' || op.policyWrite === 'update' || op.policyWrite === 'update-rule') command.option('--diff', 'read live state and show changes WITHOUT writing (requires login)');
    if (op.behavior === 'update-app' || op.policyWrite || op.userWrite || op.walletWrite || op.quorumWrite || op.organizationWrite || op.webhookWrite || op.credentialWrite || op.appClientWrite || op.domainWrite || op.settingsWrite || op.providerWrite || op.integration?.action === 'update' || op.availabilityAction === 'update' || op.advancedAction === 'merging-update' || op.advancedAction === 'captcha-update' || op.securitySetting && op.securitySetting.action !== 'read' || op.jwtAction && op.jwtAction !== 'read' || op.ecosystemConnection && op.ecosystemConnection.action !== 'list' || op.accessWrite || op.publicUserMetadata || op.publicWallet === 'archive' || op.publicOrganizationDelete || op.accountWrite || op.imageAction === 'upload' || op.imageAction === 'finalize' || op.telegram && op.telegram !== 'read') command.option('--allow-production', 'explicitly allow this production mutation; also requires --yes');
    command.addHelpText('after', '\nExamples:\n' + op.examples.map(e => `  ${e}`).join('\n') + `\n\nAPI contract: privy schema ${op.command}`
      + `\nContext: ${op.scope === 'account' ? 'explicit --account; this is workspace-scoped' : op.scope === 'app' ? 'selected app from --app, matching project, or profile; inspect project show' : 'authenticated dashboard account access'}`
      + (op.method !== 'GET' ? '\nExecute only authorized changes. Preview is offline; inspect state before retrying a failed write.' : '')
      + '\nWorkflow guides:\n' + commandGuides(op.command).map(topic => `  privy docs read ${topic}`).join('\n'));
    command.action(async (...args: any[]) => run(args.at(-1), async ({ client, config, options, context, profiles, project }) => {
      if (op.behavior === 'delete-app' && context.appSource !== 'flag') throw new CliError('EXPLICIT_APP_REQUIRED', 'Deletion requires an explicit --app <id>, even when a profile or directory selects an app.', 2);
      if (options.dryRun && options.diff) throw new CliError('CONFLICTING_OPTIONS', '--dry-run is offline; --diff reads live state. Choose one.', 2);
      if (options.maxPages && !options.all) throw new CliError('CONFLICTING_OPTIONS', '--max-pages requires --all.', 2);
      const maxPages = Number(options.maxPages ?? 10);
      if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > 100) throw new CliError('INVALID_INPUT', '--max-pages must be an integer from 1 to 100.', 2);
      const input: OperationInput = { appId: options.app ?? config.appId, accountId: options.account, params: Object.fromEntries((op.params ?? []).map((key, index) => [key, args[index]])), confirmName: options.confirmName, body: op.generatedBody ? undefined : await readBody(op, options, interrupted.signal), query: readQuery(op, options) };
      const plan = client.preview(op.id, input); // Also enforces protected-app rules for previews.
      const storageChoice = op.behavior === 'create-app' || op.credentialWrite === 'create' ? await chooseAppSecretStorage(options, interrupted.signal) : undefined;
      const imageFile = op.imageAction === 'upload' ? await readImage(args[0]) : undefined;
      if (options.dryRun) return { dryRun: true, ...plan, ...(storageChoice ? { storage: storagePreview(storageChoice) } : {}), ...(op.jwtAction || op.securitySetting || op.accountJwtFeature ? { workflow: operationSchema(op).workflow, ...(op.jwtAction === 'configure' ? { enableAuthRequested: Boolean(options.enableAuth), nonAtomicSetup: Boolean(options.enableAuth), conditionalRequests: options.enableAuth ? [{ when: 'selected app JWT authentication is disabled and all preflights pass', method: 'POST', path: `/api/v1/apps/${input.appId}/custom_jwt_auth`, body: { custom_jwt_auth: true }, order: 'before verifier configuration' }] : [] } : {}) } : {}), ...(imageFile ? { file: imageInfo(imageFile), stageOnly: Boolean(options.stageOnly), workflow: operationSchema(op).workflow } : {}), ...(options.all && op.pagination ? { pagination: { all: true, maxPages, description: 'Preview of first request; subsequent pages use next_cursor.' } } : options.all && op.ecosystemConnection ? { collection: { all: true, maxRows: 1000, requests: 1, serverPagination: false } } : {}) };
      if (options.diff) return client.diff(input, op.id);
      if (plan.mutation) requireYes(options);
      if (op.download) {
        if (!options.output) throw new CliError('OUTPUT_REQUIRED', 'Export requires --output <new-file>; user data is not printed to stdout.', 2);
        return { ...await downloadToFile(options.output, () => client.execute(op.id, input)), format: op.download };
      }
      const imageReceipt = op.imageAction === 'status' || op.imageAction === 'finalize' ? parseImageReceipt(await new ResourceSecretStore(options.profile).load({ appId: input.appId!, kind: 'image-upload', id: input.params!.upload_id }), input.appId!, input.params!.upload_id) : undefined;
      let appCredential: string | undefined;
      if (op.publicUserMetadata || op.publicWallet || op.publicOrganizationDelete) {
        if (!options.credential) throw new CliError('APP_CREDENTIAL_REQUIRED', 'Pass --credential <stored-app-credential-id>. Do not pass the secret itself.', 2);
        appCredential = await new ResourceSecretStore(options.profile).load({ appId: input.appId!, kind: 'app-credential', id: options.credential }) ?? undefined;
        if (!appCredential) throw new CliError('APP_CREDENTIAL_MISSING', 'No matching credential in this app/profile OS vault.', 2);
      }
      const preparedStorage = storageChoice ? await prepareAppSecretStorage(storageChoice, (ref, value) => persistResourceSecret(profiles, config, options.profile, ref, value)) : undefined;
      let result;
      try { result = await client.execute(op.id, input, { appSecretStorage: preparedStorage?.sink, appCredential, imageFile, imageReceipt, stageOnly: options.stageOnly, allowAccessChange: options.allowAccessChange, enableAuth: options.enableAuth, allowUnrestrictedJwt: options.allowUnrestrictedJwt, confirmWallet: options.confirmWallet, includeIdentities: options.includeIdentities, confirmAccount: options.confirmAccount, allowSelfImpact: options.allowSelfImpact, allowProduction: options.allowProduction, all: options.all, maxPages, confirmName: options.confirmName, confirmOwner: options.confirmOwner, confirmUrl: options.confirmUrl, confirmDomain: options.confirmDomain, allowSessionImpact: options.allowSessionImpact,
        storeSecret: (ref, value) => persistResourceSecret(profiles, config, options.profile, ref, value) });
      } finally { await preparedStorage?.close(); }
      if (op.browserHandoff) {
        if (options.open !== false) await openDefaultBrowser(result.review_url, interrupted.signal);
        return { ...result, browserOpened: options.open !== false };
      }
      const completedImage = (op.imageAction === 'upload' || op.imageAction === 'finalize') && result.verified === true;
      if (op.webhookWrite === 'delete' || op.credentialWrite === 'delete' || completedImage) {
        const ref = { appId: input.appId!, kind: completedImage ? 'image-upload' : op.credentialWrite ? 'app-credential' : 'webhook', id: completedImage ? result.uploadId : input.params![op.credentialWrite ? 'credential_id' : 'endpoint_id'] };
        try {
          await new ResourceSecretStore(options.profile).clear(ref);
          await profiles.save({ ...config, secretRefs: (config.secretRefs ?? []).filter(r => !sameSecretRef(r, ref)) });
        } catch {
          const error = new CliError('LOCAL_SECRET_CLEANUP_FAILED', completedImage ? 'Logo attachment verified, but checkpoint cleanup failed. Use secrets forget image-upload for this ID; do not upload again.' : 'Remote deletion was verified, but local key cleanup failed. Use secrets forget for the resource reference; do not repeat remote deletion.');
          error.details = { reference: ref, remoteVerified: true }; throw error;
        }
        return { ...result, ...(completedImage ? { checkpointCleared: true } : { localKeyCleared: true }) };
      }
      if (op.behavior === 'delete-app') {
        const refs = (config.secretRefs ?? []).filter(ref => ref.appId === input.appId);
        if (config.appId === input.appId || refs.length) {
          const next = { ...config };
          if (next.appId === input.appId) delete next.appId;
          next.secretRefs = (config.secretRefs ?? []).filter(ref => ref.appId !== input.appId);
          if (!next.secretRefs.length) delete next.secretRefs;
          try {
            const vault = new ResourceSecretStore(options.profile);
            for (const ref of refs) await vault.clear(ref);
            await profiles.save(next);
          } catch { throw new CliError('LOCAL_CONTEXT_UPDATE_FAILED', 'App deletion was verified, but local selection/resource-secret cleanup failed. Repair local context with secrets forget; do not repeat remote deletion.'); }
        }
        return { ...result, localSecretsCleared: refs.length, projectBindingNeedsUpdate: Boolean(project && context.projectApplied && project.config.appId === input.appId) };
      }
      if (options.field) {
        if (!Object.hasOwn(result, options.field)) throw new CliError('UNKNOWN_FIELD', 'That field is not present in the app configuration.', 2);
        return { [options.field]: result[options.field] };
      }
      return result;
    }));
  }
}
// Preserve the earlier bare `accounts` spelling without advertising a second API operation.
group('accounts').action(async (_opts, cmd) => run(cmd, ({ client }) => client.execute('accounts.list', {})));

const auth = group('auth');
auth.command('login').description('Verify in your normal browser, enter a login code in the terminal, and securely save the session')
  .option('--email <address>', 'dashboard email address (otherwise prompted); the login code is always entered in the terminal')
  .option('--no-open', 'print the local verification URL without opening the default browser')
  .option('--cdp <url>', 'legacy opt-in: import a shared session from an existing loopback Chrome debugging endpoint')
  .option('--timeout <seconds>', 'maximum login wait', '300')
  .option('--replace', 'replace local credentials without revoking the previous remote session')
  .action(async (_opts, cmd) => run(cmd, async ({ client, credentials, config, options }) => {
    const seconds = Number(options.timeout);
    if (!Number.isInteger(seconds) || seconds < 1 || seconds > 1800) throw new CliError('INVALID_TIMEOUT', 'Timeout must be 1–1800 seconds.', 2);
    if (options.cdp && (options.email !== undefined || options.open === false)) throw new CliError('INVALID_OPTIONS', '--cdp cannot be combined with email-login options.', 2);
    if (options.email !== undefined) validateEmail(options.email);
    if (!options.cdp) requireInteractiveLogin();
    if (await credentials.load() && !options.replace) throw new CliError('ALREADY_LOGGED_IN', 'Credentials already exist. Use another --profile, auth logout, or login --replace.', 2);
    if (options.cdp) {
      await browserLogin({ cdp: options.cdp, timeoutSeconds: seconds, signal: interrupted.signal,
        validate: value => client.validateLogin(value), save: value => credentials.save(value), log });
    } else {
      await emailLogin({ email: options.email, noOpen: options.open === false, timeoutSeconds: seconds, signal: interrupted.signal,
        validate: (value, signal) => new DashboardClient(credentials, config, undefined, signal).validateLogin(value),
        save: value => credentials.save(value), log });
    }
    return { authenticated: true, profile: options.profile, credentialStore: 'os-keychain' };
  }));
auth.command('status').description('Inspect local session expiry; optionally check remote access WITHOUT refreshing or changing credentials')
  .option('--remote', 'one account-list GET with the saved access credential; no refresh, logout or identity output')
  .action(async (_opts, cmd) => run(cmd, ({ client, options }) => client.authStatus(options.remote)));
auth.command('whoami').description('Verify remote access and show current identity and accounts')
  .action(async (_opts, cmd) => run(cmd, ({ client }) => client.whoami()));
auth.command('refresh').description('Refresh the dashboard session and persist rotated credentials')
  .action(async (_opts, cmd) => run(cmd, async ({ client }) => {
    const credentials = await client.refresh();
    return { authenticated: true, expiresAt: new Date(tokenClaims(credentials.accessToken).exp * 1000).toISOString() };
  }));
auth.command('logout').description('Revoke this session and remove local credentials, not all user sessions')
  .option('--local', 'only remove local credentials; does not revoke remote access')
  .action(async (_opts, cmd) => run(cmd, ({ client, options }) => client.logout(options.local)));

group('apps').command('use <id-or-name>').description('Select an app by ID or unambiguous name')
  .action(async (selector: string, _opts, cmd) => run(cmd, async ({ client, config, profiles }) => {
    if (config.blockedAppIds.includes(selector)) client.assertAllowed(selector);
    const matches = (await client.apps()).filter(a => a.id === selector || a.name === selector);
    if (!matches.length) throw new CliError('APP_NOT_FOUND', 'No accessible, unprotected app matched. Run apps list.', 2);
    if (matches.length > 1) throw new CliError('AMBIGUOUS_APP', 'Multiple apps matched that name. Select an exact ID from apps list.', 2);
    const app = await client.app(matches[0].id);
    await profiles.save({ ...config, appId: app.id });
    return { appId: app.id, name: app.name, env: app.env };
  }));
group('apps').command('protect <id>').description('Locally block an app; does not change it remotely')
  .action(async (id, _opts, cmd) => run(cmd, async ({ config, profiles }) => {
    validateId(id);
    const next = { ...config, blockedAppIds: [...new Set([...config.blockedAppIds, id])] };
    if (next.appId === id) delete next.appId;
    await profiles.save(next);
    return { appId: id, protected: true, scope: 'local-profile' };
  }));

group('project').command('show').description('Show effective app/profile selection and directory binding without contacting Privy')
  .action(async (_opts, cmd) => run(cmd, async ({ config, options, project, context }) => {
    const appId = options.app ?? config.appId;
    return { profile: context.profile, profileSource: context.profileSource,
      appId: appId ?? null, appSource: context.appSource ?? (config.appId ? 'profile' : null),
      appProtected: appId ? config.blockedAppIds.includes(appId) : false,
      project: project ? { ...project, applied: context.projectApplied } : null,
      remoteValidated: false };
  }));
group('project').command('init').description('Write privy.json for the selected profile/app; no remote resource is created')
  .option('--yes', 'confirm writing the local project binding')
  .option('--force', 'allow replacing an existing regular privy.json file')
  .option('--dry-run', 'preview the local file without writing it or contacting Privy')
  .action(async (_opts, cmd) => run(cmd, async ({ client, config, options }) => {
    const appId = options.app ?? config.appId;
    if (!appId) throw new CliError('APP_REQUIRED', 'Choose --app <id> or select an app with apps use before binding this directory.', 2);
    client.assertAllowed(appId);
    const value = { version: 1 as const, profile: options.profile as string, appId: appId as string };
    if (options.dryRun) return { dryRun: true, file: join(process.cwd(), PROJECT_FILE), config: value, remoteValidated: false };
    requireYes(options);
    const file = await writeProject(value, process.cwd(), Boolean(options.force));
    return { file, config: value, remoteValidated: false };
  }));

group('secrets').command('list').description('List nonsecret resource references for the selected app; no network or secret reads')
  .action(async (_opts, cmd) => run(cmd, async ({ client, config, options }) => {
    const appId = client.preview('apps.get', { appId: options.app ?? config.appId }).pathParams.app_id;
    return { appId, references: (config.secretRefs ?? []).filter(ref => ref.appId === appId), remoteValidated: false };
  }));
for (const verb of ['status', 'forget'] as const) {
  const command = group('secrets').command(`${verb} <kind> <id>`).description(verb === 'status' ? 'Check whether an app resource secret is stored locally; never reveal its value' : 'Remove a local resource secret only; does not revoke it at Privy');
  if (verb === 'forget') command.option('--yes', 'confirm removal from OS credential storage').option('--dry-run', 'show the nonsecret reference without touching credential storage');
  command.action(async (kind, id, _opts, cmd) => run(cmd, async ({ client, profiles, config, options }) => {
    const appId = client.preview('apps.get', { appId: options.app ?? config.appId }).pathParams.app_id;
    const ref = validateSecretRef({ appId, kind, id });
    if (options.dryRun) return { dryRun: true, reference: ref, remoteRevoked: false };
    const vault = new ResourceSecretStore(options.profile);
    if (verb === 'status') return { reference: ref, present: Boolean(await vault.load(ref)), valuePrinted: false, remoteValidated: false };
    requireYes(options);
    await vault.clear(ref);
    await profiles.save({ ...config, secretRefs: (config.secretRefs ?? []).filter(r => !sameSecretRef(r, ref)) });
    return { reference: ref, localSecretRemoved: true, remoteRevoked: false };
  }));
}
group('secrets').command('run <kind> <id> <program-and-args...>')
  .description('Explicitly give one stored secret to a TRUSTED child through its environment; child output is not redacted')
  .requiredOption('--env <name>', 'application environment variable for the secret; no secret value is placed in argv')
  .option('--yes', 'consent to granting this secret to the specified child program')
  .option('--dry-run', 'show the program/reference without reading the secret or executing anything')
  .action(async (kind, id, args: string[], _opts, cmd) => {
    let handoff: { value: string; variable: string } | undefined;
    await run(cmd, async ({ client, config, options }) => {
      const appId = client.preview('apps.get', { appId: options.app ?? config.appId }).pathParams.app_id;
      const ref = validateSecretRef({ appId, kind, id });
      validateSecretCommand(options.env, args);
      if (options.dryRun) return { dryRun: true, reference: ref, program: args, environmentVariable: options.env, credentialStoreRead: false };
      requireYes(options);
      const value = await new ResourceSecretStore(options.profile).load(ref);
      if (!value) throw new CliError('SECRET_NOT_FOUND', 'No secret is stored at this reference. Retrieve/import it securely first.', 2);
      handoff = { value, variable: options.env };
    });
    // Do not hold the profile lock for the lifetime of a server or a nested CLI process.
    if (handoff) process.exitCode = await runWithSecret(handoff.value, handoff.variable, args, interrupted.signal);
  });

program.command('doctor').description('Check runtime, browser, profile and credential-store access (no remote API requests)')
  .action(async (_opts, cmd) => run(cmd, async ({ credentials, config, options }) => {
    const checks: JsonObject = { runtime: { node: process.versions.node, required: '>=22.18.0' }, profile: { name: options.profile, appSelected: Boolean(options.app ?? config.appId), protectedAppCount: config.blockedAppIds.length } };
    checks.browser = { launcherAvailable: await browserLauncherAvailable(), defaultBrowserVerified: false,
      hint: 'Login uses the OS default browser. If automatic opening fails, open the local URL manually or use auth login --no-open.' };
    checks.terminal = { interactive: Boolean(process.stdin.isTTY && process.stderr.isTTY), requiredForEmailLogin: true };
    try { const value = await credentials.load(); checks.credentials = { storeAvailable: true, present: Boolean(value), remoteValidated: false }; }
    catch (error) { checks.credentials = { storeAvailable: false, code: error instanceof CliError ? error.code : 'KEYCHAIN_UNAVAILABLE', hint: 'Unlock the OS keychain/keyring. Linux requires a running Secret Service. Reinstall with optional dependencies if the native binding is missing.' }; }
    const ok = checks.credentials.storeAvailable; // A missing opener is recoverable by manually opening the URL.
    if (!ok) process.exitCode = 1;
    return { ok, checks };
  }));

interface CommandInfo { command: string; description: string; arguments: JsonObject[]; options: JsonObject[]; }
function catalog(parent = program, prefix = ''): CommandInfo[] {
  return parent.commands.flatMap(command => {
    const path = `${prefix} ${command.name()}`.trim();
    const info = { command: path, description: command.description(),
      arguments: command.registeredArguments.map(arg => ({ name: arg.name(), required: arg.required, variadic: arg.variadic })),
      options: [...program.options, ...command.options].map(option => ({ flags: option.flags, description: option.description, requiredValue: option.required, default: option.defaultValue })),
    };
    return command.commands.length ? [...(path === 'docs' ? [info] : []), ...catalog(command, path)] : [info];
  });
}
function schema(parts: string[]) {
  const path = parts.join(' ').trim();
  const op = operations.find(o => o.command === path || o.aliases?.includes(path));
  const found = catalog().find(c => c.command === path);
  if (!found) throw new CliError('UNKNOWN_COMMAND', 'Unknown command path. Use cli search or --help.', 2);
  // Static registry/Commander declarations only: no live response, credentials or user payload.
  // Generic value redaction would erase sensitive fields' *schemas*, preventing safe agent input construction.
  const has = (flag: string) => found.options.some(option => option.flags.split(/[ ,]/).includes(flag));
  const guidance = {
    context: op?.scope === 'account' ? 'Explicit --account; account-wide scope is distinct from app selection.' : op?.scope === 'app' ? 'Inspect project show; --app overrides matching project binding and saved profile selection.' : 'See the linked workflow guide for authentication or local-context requirements.',
    preview: has('--dry-run') ? '--dry-run validates offline; it does not establish remote access, eligibility or resource existence.' : null,
    diff: has('--diff') ? '--diff reads live state without writing; do not combine with --dry-run.' : null,
    consent: 'Execution/impact flags do not authorize actions beyond the user request. Ask when intent, credentials or prerequisites are missing.',
    input: has('--body') ? 'Use one body source; booleans need true/false; arrays replace complete arrays. Sensitive fields require piped JSON, never argv, chat or plaintext files.' : null,
    verification: op?.response ?? 'A successful diagnostic/local operation is not proof of remote authentication or external behavior; see the guide.',
    recovery: 'Inspect state before retrying an uncertain write. No automatic write retry or rollback. privy docs read recovery',
  };
  process.stdout.write(JSON.stringify(op ? { ...operationSchema(op), guidance, cli: found } : { ...found, kind: 'workflow', apiRequest: null, examples: localExamples[path] ?? [], guides: guideRefs(path), guidance }, null, 2) + '\n');
}
program.command('schema <command...>').description('Describe the actual API request, inputs and behavior of a command').action(schema);
group('cli').command('schema <command...>').description('Alias for privy schema').action(schema);
group('cli').command('search <terms...>').description('Search commands locally; no credentials, network or model required')
  .action((terms: string[]) => {
    const normalize = (s: string) => s.toLowerCase().replace(/configuration/g, 'config').split(/[^a-z0-9]+/).filter(Boolean).map(w => w.length > 3 && w.endsWith('s') ? w.slice(0, -1) : w);
    const words = [...new Set(normalize(terms.join(' ')))];
    const aliases = new Set(operations.flatMap(o => o.aliases ?? []));
    const results = catalog().filter(c => !aliases.has(c.command)).map(c => {
      const op = operations.find(o => o.command === c.command);
      const name = normalize(c.command), keywords = normalize(op?.keywords.join(' ') ?? ''), text = normalize(c.description);
      const phrase = normalize(terms.join(' ')).join(' ');
      const phraseMatch = words.length > 1 && op?.keywords.some(keyword => normalize(keyword).join(' ') === phrase);
      const score = words.reduce((n, w) => n + (name.includes(w) ? 5 : keywords.includes(w) ? 3 : text.includes(w) ? 1 : 0), 0) + (phraseMatch ? 5 : 0);
      return { command: `privy ${c.command}`, summary: c.description, score };
    }).filter(c => c.score > 0).sort((a, b) => b.score - a.score).slice(0, 5);
    output(results.map(({ command, summary }) => {
      const path = command.replace(/^privy /, '');
      return { command, summary, schema: `privy schema ${path}`, guide: `privy docs read ${commandGuides(path)[0]}` };
    }));
  });

const docs = program.command('docs').description('Read/search bundled workflow guides offline; no credentials or network');
docs.action(() => output({ version, offline: true, guides: guideIndex() }));
docs.addHelpText('after', '\nExamples:\n  privy docs\n  privy docs search "login providers"\n  privy docs read getting-started\n  privy docs path authentication\n\nContract: privy schema docs');
docs.command('read <topic>').description('Read one bundled Markdown guide as JSON; use docs for exact topic names')
  .action(async (topic: string) => output({ topic, version, format: 'markdown', content: await readGuide(topic) }));
docs.command('search <terms...>').description('Search bundled guide contents locally; returns up to five matches')
  .action(async (terms: string[]) => output(await searchGuides(terms)));
docs.command('path [topic]').description('Locate the bundled guide directory or one exact topic file')
  .action((topic?: string) => output({ path: guidePath(topic), version }));

// Handwritten workflows get the same just-in-time discovery pointers as API commands.
function addWorkflowHelp(parent = program, prefix = ''): void {
  for (const command of parent.commands) {
    const path = `${prefix} ${command.name()}`.trim();
    if (command.commands.length) addWorkflowHelp(command, path);
    else if (!operations.some(op => op.command === path || op.aliases?.includes(path))) {
      const examples = localExamples[path] ?? [];
      command.addHelpText('after', (examples.length ? '\nExamples:\n' + examples.map(e => `  ${e}`).join('\n') + '\n' : '')
        + `\nContract: privy schema ${path}\nWorkflow guides:\n` + commandGuides(path).map(topic => `  privy docs read ${topic}`).join('\n'));
    }
  }
}
addWorkflowHelp();
program.addHelpText('after', '\nUse search → schema → preview/diff → execute → verify.\nRisk flags acknowledge requested actions; they do not authorize extra changes.');
program.action(() => program.outputHelp());

try {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major < 22 || major === 22 && minor < 18) throw new CliError('UNSUPPORTED_NODE', 'Privy CLI requires Node.js 22.18 or later. Bun is not required.');
  await program.parseAsync();
} catch (error) {
  if (error instanceof CommanderError) {
    if (error.exitCode) {
      const hints: Record<string, string> = {
        'commander.unknownCommand': 'Unknown command. Use privy cli search "your task" or --help.',
        'commander.unknownOption': 'Unknown option. Inspect this command with --help or privy schema.',
        'commander.excessArguments': 'Too many arguments. Quote JSON bodies and inspect --help.',
        'commander.optionMissingArgument': 'An option is missing its value. Inspect this command with --help.',
        'commander.missingArgument': 'A required positional argument is missing. Inspect --help.',
      };
      console.error(JSON.stringify({ error: { code: 'USAGE_ERROR', reason: error.code, message: hints[error.code] || 'Invalid command arguments. Run the command with --help.' } }));
      process.exitCode = 2;
    }
  } else {
    const known = error instanceof CliError, cancelled = interrupted.signal.aborted;
    console.error(JSON.stringify({ error: {
      code: cancelled ? 'CANCELLED' : known ? error.code : 'INTERNAL_ERROR',
      message: cancelled ? 'Command cancelled. If a write had started, inspect remote state before retrying.' : known ? error.message : 'Unexpected failure. No credential details were printed.',
      ...(known ? { status: error.status, hint: error.hint, requestId: error.requestId, retryAfterSeconds: error.retryAfterSeconds, details: redact(error.details) } : {}),
    } }));
    process.exitCode = cancelled ? 130 : known ? error.exitCode : 1;
  }
}
