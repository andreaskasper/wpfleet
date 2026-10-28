/**
 * The hub's MCP surface: five tools instead of ~100 per site.
 *
 *   fleet_sites          which sites exist (and which this connection may use)
 *   fleet_find_tools     keyword search over the tools of all (or one) site(s)
 *   fleet_describe_tool  full description + input schema
 *   fleet_call_read      run a read-only tool on one, several or all ("*") sites
 *   fleet_call_write     run any tool on exactly one site (connection scope "write")
 *
 * Read/write is decided per site from the tool's readOnlyHint annotation, as
 * reported by that site — the same rule as the Bridge's lean profile.
 */
import type { Deps } from '../config.js';
import { audit } from '../audit.js';
import type { AccessInfo } from '../oauth/server.js';
import { listSites, siteRpc, toolAccess, toolsFor, type SiteRow, type ToolDef, SiteError } from '../sites.js';

export const PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_OUTPUT = 300_000;
const MULTI_CONCURRENCY = 4;

const callProps = {
  site: { type: 'string', description: 'Site id from fleet_sites (fleet_call_read also accepts several ids comma-separated, or "*" for all).' },
  tool: { type: 'string', description: 'Tool name from fleet_find_tools, e.g. wp_list_plugins.' },
  arguments: { type: 'object', description: 'Arguments exactly as in the inputSchema from fleet_describe_tool.' },
};

export function fleetToolDefinitions() {
  return [
    {
      name: 'fleet_sites',
      description: 'List the WordPress sites of the fleet that this connection may use: id (use it as `site`), name, URL, status, Bridge version, access level granted on that site, number of tools.',
      inputSchema: { type: 'object', properties: {} },
      annotations: { title: 'fleet sites', readOnlyHint: true, openWorldHint: false },
    },
    {
      name: 'fleet_find_tools',
      description: 'Search the tools of the fleet by keywords, e.g. "elementor widget", "updraft backup", "plugin update". Returns name, access (read/write), short description and the sites that have the tool. Without a query: all tool names. Then fleet_describe_tool for the input schema.',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Keywords (any order). Empty = list all tool names.' },
          site: { type: 'string', description: 'Only tools of this site (optional).' },
          limit: { type: 'integer', default: 25 },
        },
      },
      annotations: { title: 'fleet find tools', readOnlyHint: true, openWorldHint: false },
    },
    {
      name: 'fleet_describe_tool',
      description: 'Full description and input schema of one or more tools (comma-separated names, max 10).',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'Tool name, or several comma-separated.' },
          site: { type: 'string', description: 'Describe the tool as this site reports it (optional).' },
        },
        required: ['name'],
      },
      annotations: { title: 'fleet describe tool', readOnlyHint: true, openWorldHint: false },
    },
    {
      name: 'fleet_call_read',
      description: 'Run a READ-ONLY tool (access=read) on one site, several sites (comma-separated ids) or all sites ("*"). Multi-site calls run in parallel and return one result per site. Refuses tools that change anything.',
      inputSchema: { type: 'object', properties: callProps, required: ['site', 'tool'] },
      annotations: { title: 'fleet call read', readOnlyHint: true, openWorldHint: true },
    },
    {
      name: 'fleet_call_write',
      description: 'Run a tool that changes data (create/update/delete, plugin updates, SQL, REST proxy …) on exactly ONE site. Check the schema with fleet_describe_tool first.',
      inputSchema: { type: 'object', properties: callProps, required: ['site', 'tool'] },
      annotations: { title: 'fleet call write', readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
  ];
}

/* ---------------- helpers ---------------- */

function text(data: unknown, isError = false) {
  return { content: [{ type: 'text', text: typeof data === 'string' ? data : JSON.stringify(data, null, 1) }], isError };
}

async function allowedSites(d: Deps, acc: AccessInfo): Promise<SiteRow[]> {
  const all = await listSites(d);
  return all.filter((s) => (acc.sites === null || acc.sites.includes(s.id)) && s.mcp_url);
}

function shortDescription(t: string | undefined): string {
  let s = (t || '').replace(/\s+/g, ' ').trim();
  const m = s.match(/^(.{20,}?[.!?])\s/);
  if (m) s = m[1];
  return s.length > 180 ? s.slice(0, 179) + '…' : s;
}

interface Variant {
  tool: ToolDef;
  sites: string[];
}

interface CatalogEntry {
  /** The variant most sites report (description/schema shown by default). */
  tool: ToolDef;
  sites: string[];
  access: Set<'read' | 'write'>;
  /** All distinct definitions (different Bridge versions can differ), largest first. */
  variants: Variant[];
}

interface Catalog {
  byName: Map<string, CatalogEntry>;
}

function signature(t: ToolDef): string {
  return JSON.stringify([t.description || '', t.inputSchema || null, toolAccess(t)]);
}

async function catalog(d: Deps, sites: SiteRow[]): Promise<Catalog> {
  const raw = new Map<string, { sites: string[]; access: Set<'read' | 'write'>; variants: Map<string, Variant> }>();
  const lists = await Promise.all(sites.map(async (s) => ({ s, tools: await toolsFor(d, s) })));
  for (const { s, tools } of lists) {
    for (const t of tools) {
      const e = raw.get(t.name) || { sites: [], access: new Set<'read' | 'write'>(), variants: new Map<string, Variant>() };
      e.sites.push(s.id);
      e.access.add(toolAccess(t));
      const sig = signature(t);
      const v = e.variants.get(sig) || { tool: t, sites: [] };
      v.sites.push(s.id);
      e.variants.set(sig, v);
      raw.set(t.name, e);
    }
  }
  const byName: Catalog['byName'] = new Map();
  for (const [name, e] of raw) {
    const variants = [...e.variants.values()].sort((a, b) => b.sites.length - a.sites.length);
    byName.set(name, { tool: variants[0].tool, sites: e.sites, access: e.access, variants });
  }
  return { byName };
}

function accessLabel(set: Set<'read' | 'write'>): string {
  return set.size === 1 ? [...set][0] : 'mixed';
}

/* ---------------- tool implementations ---------------- */

async function fleetSites(d: Deps, acc: AccessInfo) {
  const sites = await allowedSites(d, acc);
  return text({
    connection_scope: acc.scope,
    sites: sites.map((s) => ({
      site: s.id,
      name: s.name,
      url: s.base_url,
      status: s.status,
      bridge_version: s.bridge_version,
      site_access: s.scope === 'full' ? 'write' : s.scope === 'read' ? 'read' : s.scope,
      tools: (() => {
        try {
          return s.tools_json ? JSON.parse(s.tools_json).length : null;
        } catch {
          return null;
        }
      })(),
      last_error: s.last_error,
    })),
  });
}

async function findTools(d: Deps, acc: AccessInfo, args: any) {
  let sites = await allowedSites(d, acc);
  if (args.site) {
    sites = sites.filter((s) => s.id === String(args.site));
    if (!sites.length) return text({ error: 'Unknown or not allowed site: ' + args.site + '. See fleet_sites.' }, true);
  }
  const cat = await catalog(d, sites);
  const limit = Math.max(1, Math.min(200, parseInt(args.limit, 10) || 25));
  const query = String(args.query || '').toLowerCase().trim();
  if (!query) {
    return text({
      total: cat.byName.size,
      sites: sites.length,
      tools: [...cat.byName.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([n, e]) => `${n} (${accessLabel(e.access)}, ${e.sites.length}/${sites.length} sites)`),
      hint: 'Search with query for short descriptions; fleet_describe_tool for schemas.',
    });
  }
  const words = query.split(/[\s_,/-]+/).filter((w) => w.length > 1);
  const hits: { score: number; name: string }[] = [];
  for (const [name, e] of cat.byName) {
    const nm = name.toLowerCase();
    const desc = (e.tool.description || '').toLowerCase();
    let score = 0;
    for (const w of words) {
      const stem = w.length > 4 ? w.replace(/s+$/, '') : w; // "plugins" finds "plugin"
      if (nm.includes(stem)) score += 3;
      else if (desc.includes(stem)) score += 1;
    }
    if (score > 0) hits.push({ score, name });
  }
  hits.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  return text({
    query,
    matches: hits.length,
    tools: hits.slice(0, limit).map((h) => {
      const e = cat.byName.get(h.name)!;
      return {
        name: h.name,
        access: accessLabel(e.access),
        description: shortDescription(e.tool.description),
        sites: e.sites.length === sites.length ? 'all' : e.sites,
        ...(e.variants.length > 1 ? { differs: 'definition differs between sites; see fleet_describe_tool' } : {}),
      };
    }),
  });
}

async function describeTool(d: Deps, acc: AccessInfo, args: any) {
  let sites = await allowedSites(d, acc);
  if (args.site) sites = sites.filter((s) => s.id === String(args.site));
  const cat = await catalog(d, sites);
  const names = [...new Set(String(args.name || '').split(',').map((s) => s.trim()).filter(Boolean))].slice(0, 10);
  const out: unknown[] = [];
  const unknown: string[] = [];
  for (const n of names) {
    const e = cat.byName.get(n);
    if (!e) {
      unknown.push(n);
      continue;
    }
    const view = (v: Variant) => ({
      access: toolAccess(v.tool),
      description: v.tool.description || '',
      inputSchema: v.tool.inputSchema || { type: 'object', properties: {} },
      annotations: v.tool.annotations || {},
    });
    if (e.variants.length === 1) {
      out.push({ name: n, ...view(e.variants[0]), sites: e.sites.length === sites.length ? 'all' : e.sites });
    } else {
      // Different Bridge versions: show every definition with the sites that report it.
      out.push({
        name: n,
        access: accessLabel(e.access),
        differs: true,
        variants: e.variants.map((v) => ({ sites: v.sites, ...view(v) })),
      });
    }
  }
  if (!out.length) return text({ error: 'Unknown tool(s): ' + (unknown.join(', ') || '(none given)') + '. Use fleet_find_tools.' }, true);
  return text({ tools: out, unknown });
}

function normArgs(a: unknown): Record<string, unknown> | null {
  if (a === undefined || a === null || a === '') return {};
  if (typeof a === 'string') {
    try {
      a = JSON.parse(a);
    } catch {
      return null;
    }
  }
  return typeof a === 'object' && !Array.isArray(a) ? (a as Record<string, unknown>) : null;
}

async function callOne(d: Deps, acc: AccessInfo, site: SiteRow, tool: string, args: Record<string, unknown>, mode: 'read' | 'write') {
  const started = Date.now();
  const tools = await toolsFor(d, site);
  const def = tools.find((t) => t.name === tool);
  if (!def) return { isError: true, error: 'Site ' + site.id + ' has no tool ' + tool + '.' };
  if (mode === 'read' && toolAccess(def) !== 'read') {
    return { isError: true, error: tool + ' can change data on ' + site.id + ' and is not available through fleet_call_read. Use fleet_call_write.' };
  }
  try {
    const r = await siteRpc(d, site, 'tools/call', { name: tool, arguments: args });
    const isError = !!r?.isError;
    await audit(d, { actor: acc.client_id, action: 'call_' + mode, site: site.id, tool, status: isError ? 'error' : 'ok', ms: Date.now() - started });
    return { isError, content: Array.isArray(r?.content) ? r.content : [] };
  } catch (e) {
    const msg = e instanceof SiteError ? e.message : 'Unexpected error.';
    await audit(d, { actor: acc.client_id, action: 'call_' + mode, site: site.id, tool, status: 'failed', ms: Date.now() - started, detail: msg });
    return { isError: true, error: msg };
  }
}

function contentText(content: any[]): string {
  return content.filter((c) => c?.type === 'text').map((c) => String(c.text)).join('\n');
}

async function callTool(d: Deps, acc: AccessInfo, args: any, mode: 'read' | 'write') {
  if (mode === 'write' && acc.scope !== 'write') {
    return text({ error: 'This connection is read-only (granted scope "read"). Reconnect WP Fleet with read + write access to change data.' }, true);
  }
  const tool = typeof args.tool === 'string' ? args.tool : '';
  const inner = normArgs(args.arguments);
  if (!tool) return text({ error: '`tool` is required.' }, true);
  if (!inner) return text({ error: '`arguments` must be an object.' }, true);
  // Reading secrets in clear text must never ride on an "always allowed" read call.
  const stripped = mode === 'read' && 'unredacted' in inner;
  if (stripped) delete inner.unredacted;
  const allowed = await allowedSites(d, acc);
  const spec = String(args.site || '').trim();
  let targets: SiteRow[];
  const multi = spec === '*' || spec.includes(',');
  if (spec === '*') targets = allowed;
  else {
    const ids = [...new Set(spec.split(',').map((s) => s.trim()).filter(Boolean))];
    const missing = ids.filter((id) => !allowed.some((s) => s.id === id));
    if (!ids.length || missing.length) return text({ error: 'Unknown or not allowed site(s): ' + (missing.join(', ') || '(none given)') + '. See fleet_sites.' }, true);
    targets = allowed.filter((s) => ids.includes(s.id));
  }
  if (mode === 'write' && (multi || targets.length !== 1)) return text({ error: 'fleet_call_write works on exactly one site.' }, true);
  if (!targets.length) return text({ error: 'No sites to call.' }, true);

  if (!multi) {
    const r = await callOne(d, acc, targets[0], tool, inner, mode);
    if ('error' in r && r.error) return text({ site: targets[0].id, error: r.error }, true);
    const content = (r as any).content as unknown[];
    if (stripped) content.push({ type: 'text', text: 'Note: `unredacted` was ignored; fleet_call_read never returns secrets. Use fleet_call_write for that (the site must grant it).' });
    return { content, isError: r.isError };
  }

  // Several sites: run in parallel (bounded), collect one entry per site.
  const results: Record<string, unknown> = {};
  let i = 0;
  const worker = async () => {
    while (i < targets.length) {
      const s = targets[i++];
      const r = await callOne(d, acc, s, tool, inner, mode);
      if ('error' in r && r.error) results[s.id] = { isError: true, error: r.error };
      else {
        const t = contentText((r as any).content);
        let data: unknown = t;
        try {
          data = JSON.parse(t);
        } catch {
          /* keep text */
        }
        results[s.id] = { isError: r.isError, result: data };
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(MULTI_CONCURRENCY, targets.length) }, worker));
  const ordered: Record<string, unknown> = {};
  for (const s of targets) ordered[s.id] = results[s.id];
  let out = JSON.stringify({ tool, sites: targets.length, results: ordered }, null, 1);
  if (out.length > MAX_OUTPUT) {
    out = out.slice(0, MAX_OUTPUT) + '\n… [truncated: ' + out.length + ' characters; call fewer sites or narrow the arguments]';
  }
  return { content: [{ type: 'text', text: out }], isError: Object.values(ordered).every((r: any) => r?.isError) };
}

/* ---------------- JSON-RPC ---------------- */

export async function instructions(d: Deps, acc: AccessInfo): Promise<string> {
  const sites = await allowedSites(d, acc);
  const list = sites.slice(0, 60).map((s) => `${s.id}${s.name && s.name !== s.id ? ' (' + s.name + ')' : ''}`).join(', ');
  return [
    `WP Fleet: one connector for ${sites.length} WordPress sites with the goo1 Claude Bridge. Sites: ${list}${sites.length > 60 ? ', …' : ''}.`,
    'Workflow: fleet_find_tools (keywords) → fleet_describe_tool (schema) → fleet_call_read or fleet_call_write with site, tool and arguments.',
    'fleet_call_read accepts site="*" or several ids to compare sites in one call (e.g. wp_list_updates, wp_site_overview).',
    acc.scope === 'write' ? 'This connection may change data via fleet_call_write (one site per call).' : 'This connection is read-only.',
    'Secrets come back as "[redacted]" from the sites; writing "[redacted]" back keeps the stored secret.',
  ].join('\n');
}

export async function handleRpc(d: Deps, acc: AccessInfo, msg: any): Promise<unknown | null> {
  const id = msg && 'id' in msg ? msg.id : undefined;
  if (id === undefined) return null; // notification
  const method = typeof msg?.method === 'string' ? msg.method : '';
  const params = msg?.params && typeof msg.params === 'object' ? msg.params : {};
  const ok = (result: unknown) => ({ jsonrpc: '2.0', id, result });
  const fail = (code: number, message: string) => ({ jsonrpc: '2.0', id, error: { code, message } });
  switch (method) {
    case 'initialize': {
      const pv = PROTOCOL_VERSIONS.includes(params.protocolVersion) ? params.protocolVersion : '2025-06-18';
      return ok({
        protocolVersion: pv,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'WP Fleet', version: '0.1.0' },
        instructions: await instructions(d, acc),
      });
    }
    case 'ping':
      return ok({});
    case 'tools/list':
      return ok({ tools: fleetToolDefinitions() });
    case 'resources/list':
      return ok({ resources: [] });
    case 'prompts/list':
      return ok({ prompts: [] });
    case 'tools/call': {
      const name = String(params.name || '');
      const args = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
      switch (name) {
        case 'fleet_sites':
          return ok(await fleetSites(d, acc));
        case 'fleet_find_tools':
          return ok(await findTools(d, acc, args));
        case 'fleet_describe_tool':
          return ok(await describeTool(d, acc, args));
        case 'fleet_call_read':
          return ok(await callTool(d, acc, args, 'read'));
        case 'fleet_call_write':
          return ok(await callTool(d, acc, args, 'write'));
        default:
          return fail(-32602, 'Unknown tool: ' + name);
      }
    }
    default:
      return fail(-32601, 'Method not found: ' + method);
  }
}
