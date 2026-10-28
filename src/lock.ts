/**
 * In-process async mutex and semaphore. Enough for the single Node process of
 * the Docker deployment; a Cloudflare Worker would need a Durable Object for
 * cross-isolate locking (documented limitation).
 */
const chains = new Map<string, Promise<unknown>>();

export async function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = chains.get(key) || Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((r) => (release = r));
  const chained = prev.then(() => mine);
  chains.set(key, chained);
  await prev.catch(() => {});
  try {
    return await fn();
  } finally {
    release();
    if (chains.get(key) === chained) chains.delete(key);
  }
}

export class Semaphore {
  private queue: (() => void)[] = [];
  private active = 0;
  constructor(private max: number) {}
  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) await new Promise<void>((r) => this.queue.push(r));
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      this.queue.shift()?.();
    }
  }
}
