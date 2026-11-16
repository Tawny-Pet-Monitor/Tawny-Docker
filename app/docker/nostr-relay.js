// The Nostr relay inside the Tawny container: the meeting point a self-hoster
// owns, at ws(s)://<this box>/relay.
//
// Tawny's devices find each other by passing sealed envelopes through a Nostr
// relay (public/nostr/transport.js). Any relay will do, and the public ones
// are the default; this one is for people who want that step on their own
// hardware too. It is deliberately not a general relay:
//
//   - It carries exactly one kind: 21059, the ephemeral gift wrap Tawny uses.
//     Anything else is refused, so nobody can use the box to publish notes.
//   - Nothing is ever stored. An envelope is handed to whoever is subscribed
//     for it right now and then it is gone; there is no database to leak.
//   - An envelope reaches only the key it is addressed to, and only after
//     that key has signed in (NIP-42), so nobody can listen on someone else's
//     inbox to learn when a camera is being watched.
//
// NIP-01 (the EVENT/REQ/CLOSE subset this needs), NIP-11, NIP-40, NIP-42.
// Clients never trust it: they check every signature and do their own
// admission, exactly as they do with a public relay.

import { WebSocketServer } from 'ws';
import { randomBytes } from 'node:crypto';
import { eventProblem, expiresAt, matchFilter, tagValue, tagValues } from '../public/nostr/nostr.js';

const KIND_WRAP = 21059;
const KIND_AUTH = 22242;
const HEX64 = /^[0-9a-f]{64}$/;

export const RELAY_LIMITS = {
  max_message_length: 128 * 1024,
  max_subscriptions: 4,
  max_filters: 2,
  max_subid_length: 64,
  max_event_tags: 8,
  max_content_length: 96 * 1024,
  created_at_upper_limit: 120,     // seconds into the future
  ephemeral_max_age: 60,           // same as strfry: older ephemeral events are refused
  events_per_10s: 80,
  max_connections: 200,
  max_per_ip: 24,
};

const nowSec = () => Math.floor(Date.now() / 1000);

/**
 * @param {object} o
 * @param {(line: string) => void} [o.log]
 * @param {string} [o.version]
 */
export function createNostrRelay({ log = () => {}, version = '' } = {}) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: RELAY_LIMITS.max_message_length });
  const conns = new Set();
  const perIp = new Map();
  const stats = { startedAt: Date.now(), relayed: 0, delivered: 0, refused: 0, lastEventAt: 0 };

  const send = (c, msg) => { if (c.ws.readyState === 1) c.ws.send(JSON.stringify(msg)); };

  function onEvent(c, ev) {
    const id = typeof ev?.id === 'string' ? ev.id.slice(0, 64) : '';
    const ok = (accepted, msg = '') => { if (!accepted) stats.refused++; send(c, ['OK', id, accepted, msg]); };
    const problem = eventProblem(ev);
    if (problem) return ok(false, 'invalid: ' + problem);
    if (ev.kind === KIND_AUTH) return ok(false, 'invalid: AUTH events go in an AUTH message, not EVENT');
    if (ev.kind !== KIND_WRAP) return ok(false, 'blocked: this relay only carries Tawny signaling (kind 21059)');
    if (ev.tags.length > RELAY_LIMITS.max_event_tags) return ok(false, 'invalid: too many tags');
    if (ev.content.length > RELAY_LIMITS.max_content_length) return ok(false, 'invalid: content too large');
    const t = nowSec();
    if (ev.created_at > t + RELAY_LIMITS.created_at_upper_limit) return ok(false, 'invalid: created_at too far in the future');
    if (ev.created_at < t - RELAY_LIMITS.ephemeral_max_age) return ok(false, 'invalid: ephemeral event is too old');
    const exp = expiresAt(ev);
    if (exp !== null && exp <= t) return ok(false, 'invalid: event has expired');
    const to = tagValues(ev, 'p');
    if (to.length !== 1 || !HEX64.test(to[0])) return ok(false, 'invalid: a gift wrap names exactly one recipient');

    if (t - c.rate.start >= 10) c.rate = { start: t, n: 0 };
    if (++c.rate.n > RELAY_LIMITS.events_per_10s) return ok(false, 'rate-limited: slow down');

    ok(true, '');
    stats.relayed++;
    stats.lastEventAt = Date.now();
    for (const other of conns) {
      if (!other.authed.has(to[0])) continue;
      for (const [subId, filters] of other.subs) {
        if (filters.some((f) => matchFilter(f, ev))) { send(other, ['EVENT', subId, ev]); stats.delivered++; break; }
      }
    }
  }

  function validFilter(f) {
    if (!f || typeof f !== 'object' || Array.isArray(f)) return false;
    for (const [k, v] of Object.entries(f)) {
      if (k === 'since' || k === 'until' || k === 'limit') { if (!Number.isInteger(v) || v < 0) return false; }
      else if (k === 'kinds') { if (!Array.isArray(v) || v.length > 8 || !v.every((x) => Number.isInteger(x))) return false; }
      else if (k === 'ids' || k === 'authors' || k === '#p') {
        if (!Array.isArray(v) || v.length > 8 || !v.every((x) => typeof x === 'string' && x.length <= 64)) return false;
      } else return false;
    }
    return true;
  }

  function onReq(c, subId, filters) {
    if (typeof subId !== 'string' || subId.length < 1 || subId.length > RELAY_LIMITS.max_subid_length) {
      return send(c, ['NOTICE', 'invalid: bad subscription id']);
    }
    const closed = (msg) => { c.subs.delete(subId); send(c, ['CLOSED', subId, msg]); };
    if (filters.length < 1 || filters.length > RELAY_LIMITS.max_filters || !filters.every(validFilter)) return closed('invalid: bad filters');
    if (!c.subs.has(subId) && c.subs.size >= RELAY_LIMITS.max_subscriptions) return closed('rate-limited: too many subscriptions');
    // The only thing to read here is envelopes addressed to you.
    if (c.authed.size === 0) return closed('auth-required: envelopes are only served to their recipient (NIP-42)');
    for (const f of filters) {
      const ps = f['#p'];
      if (!Array.isArray(ps) || ps.length === 0 || !ps.every((p) => c.authed.has(p))) {
        return closed('restricted: you can only read envelopes addressed to a key you signed in as');
      }
    }
    c.subs.set(subId, filters);
    send(c, ['EOSE', subId]);       // nothing is stored, so there is never a backlog
  }

  function onAuth(c, ev) {
    const id = typeof ev?.id === 'string' ? ev.id.slice(0, 64) : '';
    const ok = (accepted, msg = '') => send(c, ['OK', id, accepted, msg]);
    const problem = eventProblem(ev);
    if (problem) return ok(false, 'invalid: ' + problem);
    if (ev.kind !== KIND_AUTH) return ok(false, 'invalid: AUTH must be kind 22242');
    if (Math.abs(nowSec() - ev.created_at) > 600) return ok(false, 'invalid: AUTH created_at is not current');
    if (tagValue(ev, 'challenge') !== c.challenge) return ok(false, 'invalid: wrong challenge');
    // The signature must have been made for this relay, at the address this
    // very connection came in on, so a sign-in captured elsewhere is no use here.
    let url = null;
    try { url = new URL(tagValue(ev, 'relay') || ''); } catch { /* handled below */ }
    const path = url ? url.pathname.replace(/\/+$/, '') : '';
    if (!url || !/^wss?:$/.test(url.protocol) || url.host.toLowerCase() !== c.host || path !== c.path) {
      return ok(false, 'invalid: AUTH is for another relay');
    }
    if (c.authed.size >= 4) return ok(false, 'restricted: too many identities on one connection');
    c.authed.add(ev.pubkey);
    ok(true, '');
  }

  function onMessage(c, raw) {
    let msg;
    try { msg = JSON.parse(raw); } catch { return send(c, ['NOTICE', 'invalid: not JSON']); }
    if (!Array.isArray(msg)) return send(c, ['NOTICE', 'invalid: expected a JSON array']);
    const [type, ...rest] = msg;
    switch (type) {
      case 'EVENT': return onEvent(c, rest[0]);
      case 'REQ': return onReq(c, rest[0], rest.slice(1));
      case 'CLOSE': c.subs.delete(rest[0]); return undefined;
      case 'AUTH': return onAuth(c, rest[0]);
      default: return send(c, ['NOTICE', 'invalid: unknown message type']);
    }
  }

  wss.on('connection', (ws, _req, ctx) => {
    const c = {
      ws, ip: ctx.ip, host: ctx.host, path: ctx.path,
      challenge: randomBytes(16).toString('hex'),
      authed: new Set(), subs: new Map(), rate: { start: nowSec(), n: 0 }, alive: true,
    };
    conns.add(c);
    perIp.set(c.ip, (perIp.get(c.ip) || 0) + 1);
    const gone = () => {
      if (!conns.delete(c)) return;
      const n = (perIp.get(c.ip) || 1) - 1;
      if (n <= 0) perIp.delete(c.ip); else perIp.set(c.ip, n);
    };
    send(c, ['AUTH', c.challenge]);
    ws.on('pong', () => { c.alive = true; });
    ws.on('message', (data, isBinary) => {
      if (isBinary) return send(c, ['NOTICE', 'invalid: binary frames are not Nostr']);
      onMessage(c, data.toString('utf8'));
    });
    ws.on('close', gone);
    ws.on('error', gone);
  });

  // Drop connections that stopped answering, so a phone that walked out of
  // range does not hold a slot for ever.
  const sweep = setInterval(() => {
    for (const c of conns) {
      if (!c.alive) { try { c.ws.terminate(); } catch { /* already gone */ } continue; }
      c.alive = false;
      try { c.ws.ping(); } catch { /* closing */ }
    }
  }, 30000);
  sweep.unref?.();

  return {
    /**
     * Take over a WebSocket upgrade for the relay path. The caller has already
     * vetted the Host header.
     * @param {{ ip: string, host: string, path: string }} ctx  `host` is the
     *   host[:port] the client used; `path` the path without a trailing slash
     */
    handleUpgrade(req, socket, head, ctx) {
      const deny = (code, why) => { socket.write(`HTTP/1.1 ${code} ${why}\r\nConnection: close\r\n\r\n`); socket.destroy(); };
      if (conns.size >= RELAY_LIMITS.max_connections) return deny(503, 'Service Unavailable');
      if ((perIp.get(ctx.ip) || 0) >= RELAY_LIMITS.max_per_ip) return deny(429, 'Too Many Requests');
      wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req, { ...ctx, host: String(ctx.host).toLowerCase() }));
    },
    /** NIP-11: what this relay is and what it will take. */
    info() {
      return {
        name: 'Tawny relay',
        description: 'Carries sealed Tawny signaling envelopes (kind 21059) to their recipient. Stores nothing.',
        supported_nips: [1, 11, 40, 42],
        software: 'https://github.com/Tawny-Pet-Monitor/Tawny-Docker',
        version,
        limitation: {
          max_message_length: RELAY_LIMITS.max_message_length,
          max_subscriptions: RELAY_LIMITS.max_subscriptions,
          max_subid_length: RELAY_LIMITS.max_subid_length,
          max_event_tags: RELAY_LIMITS.max_event_tags,
          max_content_length: RELAY_LIMITS.max_content_length,
          created_at_upper_limit: RELAY_LIMITS.created_at_upper_limit,
          auth_required: false,
          payment_required: false,
          restricted_writes: true,
        },
      };
    },
    /** For /setup: is anyone on it, has it carried anything. No keys, no addresses. */
    status() {
      let signedIn = 0;
      for (const c of conns) if (c.authed.size) signedIn++;
      return {
        connections: conns.size, signedIn,
        relayed: stats.relayed, delivered: stats.delivered, refused: stats.refused,
        lastEventAt: stats.lastEventAt || null, startedAt: stats.startedAt,
      };
    },
    close() { clearInterval(sweep); for (const c of conns) { try { c.ws.terminate(); } catch { /* gone */ } } wss.close(); },
  };
}
