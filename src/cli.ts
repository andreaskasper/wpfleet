/**
 * Admin CLI (run inside the container):
 *   node dist/cli.js admin-create --user andreas     create the admin (asks for the password)
 *   node dist/cli.js admin-password                  set a new password (logs out all sessions)
 *   node dist/cli.js totp-reset                      remove the authenticator (enrol again at next login)
 *   node dist/cli.js sites                           list sites and their status
 * The password is read from the terminal (hidden) or, non-interactively,
 * from the environment variable FLEET_NEW_PASSWORD.
 */
import { createInterface } from 'node:readline';
import { nodeDeps } from './node.js';
import { createAdmin, getAdmin, resetTotp, setPassword } from './auth.js';
import { listSites } from './sites.js';

function ask(question: string, hidden: boolean): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) {
      // Mute echo after printing the question.
      const out = rl as unknown as { _writeToOutput: (s: string) => void; output: NodeJS.WriteStream };
      out._writeToOutput = (s: string) => {
        if (s.includes(question)) out.output.write(s);
      };
    }
    rl.question(question, (a) => {
      rl.close();
      if (hidden) process.stdout.write('\n');
      resolve(a);
    });
  });
}

async function readPassword(): Promise<string> {
  if (process.env.FLEET_NEW_PASSWORD) return process.env.FLEET_NEW_PASSWORD;
  if (!process.stdin.isTTY) throw new Error('No terminal: run with `docker exec -it …` or set FLEET_NEW_PASSWORD.');
  const a = await ask('Password (min. 12 characters): ', true);
  const b = await ask('Repeat password: ', true);
  if (a !== b) throw new Error('The passwords differ.');
  return a;
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const arg = (name: string) => {
    const i = rest.indexOf('--' + name);
    return i >= 0 ? rest[i + 1] : undefined;
  };
  const d = await nodeDeps();
  switch (cmd) {
    case 'admin-create': {
      const user = arg('user');
      if (!user) throw new Error('Usage: admin-create --user <name>');
      if (await getAdmin(d)) throw new Error('An admin exists already. Use admin-password to change the password.');
      await createAdmin(d, user, await readPassword());
      console.log(`Admin "${user}" created. Log in at ${d.cfg.publicUrl}/login and set up the authenticator.`);
      break;
    }
    case 'admin-password':
      if (!(await getAdmin(d))) throw new Error('No admin yet: use admin-create.');
      await setPassword(d, await readPassword());
      console.log('Password changed; all sessions were logged out.');
      break;
    case 'totp-reset':
      await resetTotp(d);
      console.log('Authenticator removed. Log in with the password and set it up again.');
      break;
    case 'sites':
      for (const s of await listSites(d)) console.log(`${s.id}\t${s.status}\t${s.scope || '-'}\t${s.bridge_version || '-'}\t${s.base_url}`);
      break;
    default:
      console.log('Commands: admin-create --user <name> | admin-password | totp-reset | sites');
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
