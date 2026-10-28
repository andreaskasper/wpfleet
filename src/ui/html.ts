/** Tiny server-side HTML helpers (no external resources, strict CSP). */

export function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** Marks a string as already-escaped HTML. */
export class Raw {
  constructor(public html: string) {}
}
export const raw = (s: string) => new Raw(s);

export function h(strings: TemplateStringsArray, ...values: unknown[]): Raw {
  let out = '';
  strings.forEach((s, i) => {
    out += s;
    if (i < values.length) {
      const v = values[i];
      if (v instanceof Raw) out += v.html;
      else if (Array.isArray(v)) out += v.map((x) => (x instanceof Raw ? x.html : esc(x))).join('');
      else if (v === null || v === undefined || v === false) out += '';
      else out += esc(v);
    }
  });
  return new Raw(out);
}

const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2327;--muted:#646970;--line:#dcdcde;--accent:#2563eb;--ok:#15803d;--warn:#b45309;--bad:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1b1f24;--fg:#e6e8eb;--muted:#9aa4af;--line:#2c333b;--accent:#60a5fa;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid var(--line);background:var(--card)}
header b{font-size:17px}main{max-width:1000px;margin:0 auto;padding:20px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:0 0 18px}
h1{font-size:20px;margin:0 0 12px}h2{font-size:16px;margin:0 0 12px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}.muted{color:var(--muted);font-size:13px}code{font-size:12.5px;word-break:break-all}
input[type=text],input[type=password],input[type=url]{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font-size:15px}
label{display:block;margin:0 0 10px}label span{display:block;font-size:13px;color:var(--muted);margin-bottom:3px}
button,.btn{display:inline-block;padding:8px 14px;border-radius:6px;border:1px solid var(--accent);background:var(--accent);color:#fff;font-weight:600;font-size:14px;cursor:pointer;text-decoration:none}
button.sec,.btn.sec{background:transparent;color:var(--accent)}button.danger{background:transparent;border-color:var(--bad);color:var(--bad)}
form.inline{display:inline}.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}.row>label{flex:1;min-width:200px}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;border:1px solid currentColor}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.msg{padding:10px 14px;border-radius:8px;margin:0 0 16px;border:1px solid var(--line)}.msg.err{border-color:var(--bad);color:var(--bad)}.msg.okm{border-color:var(--ok);color:var(--ok)}
.narrow{max-width:420px;margin:40px auto}.qr svg{width:220px;height:220px;background:#fff;padding:8px;border-radius:8px}
fieldset{border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:0 0 14px}legend{font-weight:600;padding:0 6px}
.opt{display:flex;gap:8px;align-items:flex-start;margin:6px 0}.opt input{margin-top:4px}
@media (max-width:640px){th:nth-child(n+4),td:nth-child(n+4){display:none}}
`;

export function page(title: string, body: Raw, opts: { user?: string; csrf?: string } = {}): string {
  const nav = opts.user
    ? h`<nav><span class="muted">${opts.user}</span> &nbsp; <form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="${opts.csrf}"><button class="sec" type="submit">Log out</button></form></nav>`
    : h``;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${esc(title)} · WP Fleet</title><style>${CSS}</style></head><body><header><b>WP Fleet</b>${nav.html}</header><main>${body.html}</main></body></html>`;
}

export function message(text: string | null | undefined, kind: 'err' | 'okm' = 'err'): Raw {
  return text ? h`<div class="msg ${kind}">${text}</div>` : h``;
}

export function fmtTime(t: number | null | undefined): string {
  if (!t) return '—';
  return new Date(t * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}
