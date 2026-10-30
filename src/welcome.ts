const banner = [
  ['██████╗ ██████╗ ██╗██╗   ██╗██╗   ██╗', ' ██████╗██╗     ██╗'],
  ['██╔══██╗██╔══██╗██║██║   ██║╚██╗ ██╔╝', '██╔════╝██║     ██║'],
  ['██████╔╝██████╔╝██║██║   ██║ ╚████╔╝ ', '██║     ██║     ██║'],
  ['██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝  ╚██╔╝  ', '██║     ██║     ██║'],
  ['██║     ██║  ██║██║ ╚████╔╝    ██║   ', '╚██████╗███████╗██║'],
  ['╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝     ╚═╝   ', ' ╚═════╝╚══════╝╚═╝'],
].map(([privy, cli]) => privy.padEnd(40) + cli).join('\n');

/** Human-only welcome; the caller keeps help, flagged invocations and pipes unchanged. */
export function printWelcome(version: string): void {
  const depth = process.env.NO_COLOR !== undefined || process.env.NODE_DISABLE_COLORS !== undefined || process.env.TERM === 'dumb'
    ? 1 : process.stdout.getColorDepth();
  const blue = depth >= 24 ? '\x1b[38;2;196;212;246m' : depth >= 8 ? '\x1b[38;5;153m' : depth >= 4 ? '\x1b[94m' : '';
  const grey = depth >= 4 ? '\x1b[90m' : '';
  const paint = (text: string, color: string) => color ? `${color}${text}\x1b[0m` : text;
  process.stdout.write(`\n${paint(banner, blue)}\n\n${paint(`v${version}`, grey)}  (un)official Privy CLI\nManage Privy from your agent or terminal.\n\nGet started:\n  privy auth login          Sign in or renew your saved session\n  privy docs                Browse offline workflow guides\n  privy search "your task"   Find the right command\n  privy --help              See all commands and options\n\n`);
}
