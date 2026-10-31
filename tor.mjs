// Tor exit lanes for zen-proxy.
//
// zen-proxy spends one address. Its identity work (harness preamble, tool
// manifest, minted session) gets it *past* the gate, but the free tier meters
// per exit IP — 200 requests a day each, resetting at 00:00 UTC — so a single
// address still runs dry while the proxy is otherwise healthy.
//
// This file is the lingling half of the problem, ported to the shape zen-proxy
// already has: every lane is its own tor process pinned to its own exit relay,
// a model call goes down a wave of lanes at once, the first 200 takes the
// client and the rest are cut. What lingling does over a local CONNECT relay
// with a minted CA, this does with `fetch(url, { proxy })` — Bun's fetch speaks
// HTTP CONNECT (it does NOT speak socks5: "UnsupportedProxyProtocol"), so each
// lane exposes tor's HTTPTunnelPort and the request goes out natively. Nothing
// terminates TLS but Bun, so the TLS/HTTP fingerprint the gate checks is
// untouched: the exit IP changes, the client stack does not.
//
// Two things are deliberately *not* carried over:
//
//   * No MITM. zen-proxy is already the client, so it can see its own request.
//   * No request rewriting. Racing copies are byte-identical; only the lane's
//     exit and the lane's minted identity pair differ.
//
// The identity pair is the one place this and lingling disagree, and it is
// worth being explicit: lingling forwards the real client's identity untouched
// and only moves the IP. Here the pair is minted per *lane*, and rotates with
// the lane's exit — because the gate's 403 FreeTierError is what one session
// arriving from a dozen addresses earns (lingling's own measurements: five
// lanes answer 200, ten are refused from the first call). Rotating both halves
// together keeps "one CLI conversation in one project" true per address instead
// of stretching one session across the whole fleet.
//
// A client that brings its own `x-opencode-session` is the exception: its
// identity is never rotated for it, so it is pinned to a single lane instead of
// being raced from five addresses. That is the same rule lingling follows by
// never touching a session id — just enforced by not fanning it out.

import { spawn, execFile } from "node:child_process"
import { randomBytes } from "node:crypto"
import fs from "node:fs"
import net from "node:net"
import os from "node:os"
import path from "node:path"
import zlib from "node:zlib"

// Reasons an exit sits out, mirroring lingling's notepad sections.
export const FREE_LIMIT = "free-limit" // 200/day spent; until the reset it names
export const RATE_LIMIT = "rate-limit" // short burst ceiling; ~25 min
export const GATE = "gate" // 403 FreeTierError; minutes, not a day
export const TIMEOUT = "timeout" // slow or dead exit; written off on the spot
export const BLOCKED = "blocked" // exit unreachable / refused to build a circuit

// The day's wall: 200 requests per exit IP, resetting at 00:00 UTC.
export const EXIT_CAP = 200
// A short burst ceiling opencode neither documents nor headers.
const RATE_COOLDOWN_MS = 25 * 60_000
// A gate verdict is about the client, not the address: minutes, never a day.
const GATE_COOLDOWN_MS = 5 * 60_000
const TIMEOUT_COOLDOWN_MS = 10 * 60_000
const BLOCKED_COOLDOWN_MS = 2 * 60_000

const DEFAULT_COUNTRIES = ["us", "de", "nl", "fr", "ro", "gb", "ca", "se", "pl", "ch"]
const CONSENSUS_TTL_MS = 10 * 60_000
const ONIONOO = "https://onionoo.torproject.org/details"
const TOR_CHECK = "https://check.torproject.org/api/ip"
// Where lingling gets its private tor from, and where this gets one too.
const TOR_DIST_URL = "https://dist.torproject.org/torbrowser/"

// ---------------------------------------------------------------------------
// small shared helpers (exported: the proxy's own tests exercise them)
// ---------------------------------------------------------------------------

/** The next 00:00 UTC after `now` — what a free-limit 429 without a header means. */
export function nextUtcMidnight(now = Date.now()) {
  const d = new Date(now)
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1, 0, 0, 0, 0)
}

/** The 00:00 UTC before `now` — the day an exit's allowance belongs to. */
export function utcDayStart(now = Date.now()) {
  const d = new Date(now)
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate())
}

/** A `retry-after` in seconds (or an HTTP date), as an absolute epoch ms. */
export function retryAfterMs(value, now = Date.now()) {
  if (value == null || value === "") return 0
  const n = Number(value)
  if (Number.isFinite(n)) return n > 0 ? now + n * 1000 : 0
  const t = Date.parse(String(value))
  return Number.isFinite(t) ? Math.max(0, t - now) : 0
}

/**
 * Which notepad section a 429 or 403 belongs in.
 *
 * The two 429s are not the same thing and the difference decides how long an
 * exit sits out: the day's wall resets at 00:00 UTC, the burst ceiling lifts in
 * minutes. `Endpoint is unavailable` is opencode's own edge having a bad
 * moment — never written down against the exit at all.
 */
export function classifyFailure(status, bodyText = "", retryHeader = null, now = Date.now()) {
  const text = String(bodyText || "")
  if (status === 403) {
    const gated = /FreeTierError|free tier/i.test(text)
    return {
      reason: gated ? GATE : BLOCKED,
      until: now + (gated ? GATE_COOLDOWN_MS : BLOCKED_COOLDOWN_MS),
      edge: false,
    }
  }
  if (status === 429) {
    if (/Endpoint is unavailable/i.test(text)) return { reason: null, until: 0, edge: true }
    // Both branches work in *durations*: retryAfterMs returns an absolute
    // deadline, so it is compared against `now` before anything is clamped.
    if (/FreeUsageLimitError|Free usage limit/i.test(text)) {
      const named = retryAfterMs(retryHeader, now)
      // Never write an exit off for more than a day: reports exist of the wall
      // sticking past midnight UTC, and a stale ledger outlives its truth.
      const span = named > 0 ? Math.min(named - now, 24 * 3600_000) : nextUtcMidnight(now) - now
      return { reason: FREE_LIMIT, until: now + Math.max(60_000, span), edge: false }
    }
    const named = retryAfterMs(retryHeader, now)
    const span = named > 0 ? Math.min(named - now, RATE_COOLDOWN_MS) : RATE_COOLDOWN_MS
    return { reason: RATE_LIMIT, until: now + Math.max(60_000, span), edge: false }
  }
  return { reason: null, until: 0, edge: false }
}

/**
 * lingling's `countries.txt`: three optional lines — primary, fallback,
 * preferred — of comma-separated two-letter codes, `#` starts a comment and a
 * comment-only line is skipped entirely. A missing file is not an error: the
 * defaults are fine.
 */
export function parseCountries(text) {
  const pools = [[], [], []]
  if (!text) return { primary: [], fallback: [], preferred: [] }
  const lines = []
  for (const raw of String(text).split(/\r?\n/)) {
    if (raw.includes("#")) {
      const cut = raw.split("#", 1)[0]
      if (!cut.trim()) continue
      lines.push(cut)
    } else {
      lines.push(raw)
    }
  }
  // A blank line is a skipped pool, not "advance to the next one", so index by
  // position rather than pushing: `us,de` then a blank then `fr` must not read
  // as primary=[us,de,fr].
  lines.slice(0, 3).forEach((line, i) => {
    pools[i] = line
      .split(",")
      .map((c) => c.trim().toLowerCase())
      .filter((c) => /^[a-z]{2}$/.test(c))
  })
  const [primary, fallback, preferred] = pools
  return { primary, fallback, preferred }
}

// ---------------------------------------------------------------------------
// the ledger: which exit sits out, until when, and why
// ---------------------------------------------------------------------------

export class Ledger {
  constructor(statePath = "", now = () => Date.now()) {
    this.statePath = statePath
    this.now = now
    // fingerprint -> { until, reason }
    this.entries = new Map()
    // fingerprint -> { requests, since }
    this.usage = new Map()
    this.load()
  }

  limited(fingerprint) {
    if (!fingerprint) return false
    const entry = this.entries.get(fingerprint)
    if (!entry) return false
    if (entry.until <= this.now()) {
      this.entries.delete(fingerprint)
      return false
    }
    return true
  }

  reasonFor(fingerprint) {
    const entry = this.entries.get(fingerprint)
    if (!entry || entry.until <= this.now()) return ""
    return entry.reason
  }

  note(fingerprint, reason, until) {
    if (!fingerprint || !reason) return false
    const previous = this.entries.get(fingerprint)
    // Never shorten a verdict already on the books: a 429 rate limit arriving
    // behind a day's wall must not hand the address back early.
    const keep = previous && previous.until > until ? previous : { reason, until }
    this.entries.set(fingerprint, keep)
    this.save()
    return true
  }

  /** A real 200 clears the exit's record — a refusal is not permanent. */
  noteOk(fingerprint) {
    if (!fingerprint) return false
    const cleared = this.entries.delete(fingerprint)
    if (cleared) this.save()
    return cleared
  }

  spend(fingerprint) {
    if (!fingerprint) return 0
    const now = this.now()
    const row = this.usage.get(fingerprint) || { requests: 0, since: now }
    // An exit's allowance is per UTC day. A row that started before today's
    // midnight describes yesterday's spending, not today's.
    if (row.since && row.since < utcDayStart(now)) {
      row.requests = 0
      row.since = now
    }
    row.requests += 1
    this.usage.set(fingerprint, row)
    return row.requests
  }

  usageFor(fingerprint) {
    const row = this.usage.get(fingerprint)
    if (!row) return { requests: 0, since: 0 }
    if (row.since && row.since < utcDayStart(this.now())) return { requests: 0, since: row.since }
    return row
  }

  forget(fingerprint) {
    this.usage.delete(fingerprint)
  }

  summary() {
    const out = {}
    for (const [fp, entry] of this.entries) {
      if (entry.until > this.now()) out[fp] = { reason: entry.reason, until: entry.until }
    }
    return out
  }

  load() {
    if (!this.statePath || !fs.existsSync(this.statePath)) return
    try {
      const raw = JSON.parse(fs.readFileSync(this.statePath, "utf8"))
      for (const [fp, entry] of Object.entries(raw.entries || {})) {
        if (entry && entry.until > this.now()) this.entries.set(fp, { reason: entry.reason, until: entry.until })
      }
      for (const [fp, row] of Object.entries(raw.usage || {})) {
        if (row && typeof row.requests === "number") this.usage.set(fp, { requests: row.requests, since: row.since || 0 })
      }
    } catch {
      // A corrupt ledger is a cold ledger: re-learning a spent exit costs one
      // 429, while refusing to boot over a bad JSON file costs the feature.
    }
  }

  save() {
    if (!this.statePath) return
    try {
      fs.mkdirSync(path.dirname(this.statePath), { recursive: true })
      fs.writeFileSync(
        this.statePath,
        JSON.stringify({ entries: this.summary(), usage: Object.fromEntries(this.usage) }, null, 2),
      )
    } catch {
      // Best effort: the ledger is an optimisation, not the source of truth.
    }
  }
}

// ---------------------------------------------------------------------------
// exit discovery: fresh relays, distinct, country-filtered
// ---------------------------------------------------------------------------

/**
 * Usable exit relays from Onionoo, grouped by country.
 *
 * lingling reads the live consensus over tor's control protocol (it has stem
 * for that); a zero-dependency JS module does not, and Onionoo publishes the
 * same facts as JSON. The semantics are the ones that matter: only relays that
 * carry the Exit flag, are running, and are not known-bad.
 */
export async function discoverExits({ signal, hydrate = false } = {}) {
  const fields = "fingerprint,nickname,country,exit_addresses,flags"
  const url = `${ONIONOO}?type=relay&running=true&flag=Exit&fields=${fields}`
  const res = await fetch(url, { signal: signal ?? AbortSignal.timeout(20_000) })
  if (!res.ok) throw new Error(`onionoo ${res.status}`)
  const parsed = await res.json()
  const relays = Array.isArray(parsed.relays) ? parsed.relays : []
  const byCountry = new Map()
  for (const relay of relays) {
    const fingerprint = String(relay.fingerprint || "").toUpperCase()
    const cc = String(relay.country || "").toLowerCase()
    if (!/^[0-9A-F]{40}$/.test(fingerprint) || !/^[a-z]{2}$/.test(cc)) continue
    const flags = Array.isArray(relay.flags) ? relay.flags : []
    if (flags.length && !flags.includes("Exit")) continue
    if (!byCountry.has(cc)) byCountry.set(cc, [])
    byCountry.get(cc).push({ fingerprint, nickname: String(relay.nickname || ""), country: cc })
  }
  return { relays, byCountry }
}

// ---------------------------------------------------------------------------
// getting a tor that can still join the network
// ---------------------------------------------------------------------------

/**
 * The Expert Bundle asset name for this platform.
 * Windows: windows-x86_64, macOS: macos-aarch64, Linux: linux-x86_64.
 */
export function torAsset(platform = process.platform, arch = process.arch) {
  const osName = platform === "win32" ? "windows" : platform === "darwin" ? "macos" : "linux"
  const archName =
    arch === "x64" ? "x86_64" : arch === "arm64" ? "aarch64" : arch === "ia32" ? "i686" : arch
  return `tor-expert-bundle-${osName}-${archName}`
}

/**
 * Minimal tar reader: the Expert Bundle is a .tar.gz and this project has no
 * dependencies, so the two things tar actually needs here — 512-byte headers
 * and a zip-free gunzip — are done by hand.
 *
 * Returns [{ name, data }]. Absolute paths and `..` segments are dropped rather
 * than written: an archive is untrusted input even when it is expected.
 */
export function unpackTarGz(buffer) {
  const tar = zlib.gunzipSync(buffer)
  const out = []
  let offset = 0
  let longName = ""
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512)
    if (header.every((b) => b === 0)) break // end-of-archive marker
    const rawName = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "")
    const sizeField = header.subarray(124, 136).toString("utf8").replace(/\0.*$/, "").trim()
    const size = parseInt(sizeField, 8) || 0
    const type = String.fromCharCode(header[156] || 48)
    const prefix = header.subarray(345, 500).toString("utf8").replace(/\0.*$/, "")
    const data = tar.subarray(offset + 512, offset + 512 + size)
    offset += 512 + Math.ceil(size / 512) * 512
    if (type === "L") {
      // GNU long name: the payload renames the *next* entry.
      longName = data.toString("utf8").replace(/\0.*$/, "")
      continue
    }
    const name = (longName || (prefix ? `${prefix}/${rawName}` : rawName)).replace(/\\/g, "/")
    longName = ""
    if (!name || name.includes("..") || name.startsWith("/")) continue
    if (type !== "0" && type !== "7" && type !== "\0" && type !== "5") continue
    if (type === "5") continue
    out.push({ name, data: Buffer.from(data) })
  }
  return out
}

/** `tor` on PATH, with the Windows extensions PATH lookups actually honour. */
export function findOnPath(name, env = process.env, platform = process.platform) {
  const exts = platform === "win32" ? (env.PATHEXT || ".EXE;.CMD;.BAT").split(";").filter(Boolean) : [""]
  const dirs = String(env.PATH || env.Path || "").split(platform === "win32" ? ";" : ":").filter(Boolean)
  const wantsExt = platform === "win32" && !/\.[a-z0-9]+$/i.test(name)
  for (const dir of dirs) {
    for (const ext of wantsExt ? exts : [""]) {
      const candidate = path.join(dir, name + (wantsExt ? ext.toLowerCase() : ext))
      try {
        if (fs.statSync(candidate).isFile()) return candidate
      } catch {}
      if (wantsExt) {
        const upper = path.join(dir, name + ext.toUpperCase())
        try {
          if (fs.statSync(upper).isFile()) return upper
        } catch {}
      }
    }
  }
  return ""
}

/**
 * The tor binary inside an extracted bundle.
 *
 * The Expert Bundle keeps `tor/tor.exe` at the archive root today, but the
 * layout is not a contract and lingling always searched for it. Walking the
 * tree costs a few stat calls and survives a future bundle that nests itself
 * under a version directory.
 */
export function findTorUnder(root, exe = process.platform === "win32" ? "tor.exe" : "tor") {
  if (!root) return ""
  const queue = [root]
  const seen = new Set()
  while (queue.length) {
    const dir = queue.shift()
    if (seen.has(dir)) continue
    seen.add(dir)
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name)
      if (entry.isFile() && entry.name.toLowerCase() === exe.toLowerCase()) return full
      if (entry.isDirectory()) queue.push(full)
    }
  }
  return ""
}

/**
 * The bundle's geoip databases, when the tor binary sits beside them.
 *
 * Pinning an exit by fingerprint does not need them, but a lane with no fresh
 * relay lets tor choose (and a country hint would need `{cc}`), so using the
 * databases that shipped next to the binary costs nothing and silences tor's
 * "GEOIP file is missing" warnings.
 */
export function geoipFor(torBinary) {
  if (!torBinary) return {}
  const dir = path.dirname(torBinary)
  for (const root of [path.join(dir, "..", "data"), dir, path.join(dir, "..")]) {
    const geoip = path.join(root, "geoip")
    try {
      if (!fs.statSync(geoip).isFile()) continue
    } catch {
      continue
    }
    const geoip6 = path.join(root, "geoip6")
    return { geoip, geoip6: fs.existsSync(geoip6) ? geoip6 : "" }
  }
  return {}
}

/**
 * A tor that can actually join today's network.
 *
 * The order is lingling's, and each step exists for a reason: an explicit
 * override wins because the operator said so; a bundle from a previous run is
 * reused because the download is 30 MB; a system tor is preferred next because
 * it is already there; and only then is the Expert Bundle fetched into the data
 * directory. A stale system tor is the common case — 0.4.7 predates the current
 * consensus protocol and refuses to be a client at all — which is exactly why
 * the download exists rather than trusting PATH.
 */
/**
 * The oldest tor that can still join today's network. The current consensus
 * requires protocol versions (Desc=3, Microdesc=3) that 0.4.7 and older do not
 * speak — they start, write a cookie, open a control port, and then sit at 0%
 * forever. A tor that old is a trap, not a tor, so auto-discovery refuses it and
 * falls through to the bundle.
 */
function parseTorVersion(out) {
  const m = /Tor version ([0-9]+)\.([0-9]+)\.([0-9]+)/.exec(String(out))
  if (!m) return null
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) }
}

function versionAtLeast(v, major, minor, patch) {
  if (!v) return false
  if (v.major !== major) return v.major > major
  if (v.minor !== minor) return v.minor > minor
  return v.patch >= patch
}

/** `tor --version`, or null when it cannot run / does not report a version. */
function torVersion(binPath) {
  return new Promise((resolve) => {
    execFile(binPath, ["--version"], { timeout: 10_000, windowsHide: true }, (err, stdout) => {
      if (err) return resolve(null)
      resolve(parseTorVersion(stdout))
    })
  })
}

export async function ensureTorBinary({ dataDir, override = "", download = true, log = () => {}, versionOf = torVersion } = {}) {
  const exe = process.platform === "win32" ? "tor.exe" : "tor"
  if (override) {
    // An explicit override wins because the operator said so — the version gate
    // is for auto-discovery only, where a stale tor is indistinguishable from
    // "tor is installed".
    if (!fs.existsSync(override)) throw new Error(`torBinary not found: ${override}`)
    return override
  }
  // A candidate is usable only if its reported version can speak the current
  // consensus protocol; a too-old or silent tor is skipped, never returned.
  const usable = async (bin) => {
    if (!bin) return ""
    const v = await versionOf(bin)
    if (versionAtLeast(v, 0, 4, 8)) return bin
    log(
      `tor: ${bin} is ${v ? `tor ${v.major}.${v.minor}.${v.patch}` : "unrecognised"} — too old for today's network; looking for a fresher tor`,
    )
    return ""
  }
  const toolsDir = path.join(dataDir, "tools")
  const bundled = await usable(findTorUnder(toolsDir, exe))
  if (bundled) return bundled
  const onPath = await usable(findOnPath(exe))
  if (onPath) return onPath
  if (!download) throw new Error(`no usable tor found (need >= 0.4.8); set TOR_BIN or a "torBinary" in the config`)
  await downloadTorBundle({ toolsDir, log })
  const located = await usable(findTorUnder(toolsDir, exe))
  if (!located) {
    throw new Error("the Tor bundle downloaded but no usable tor binary was found inside it")
  }
  return located
}

/** Fetch the newest Expert Bundle and unpack it beside the lane data. */
export async function downloadTorBundle({ toolsDir, log = () => {} }) {
  log(`tor: downloading the Tor Expert Bundle (~30 MB, once) into ${toolsDir}`)
  const listing = await fetch(TOR_DIST_URL, { signal: AbortSignal.timeout(30_000) }).then((r) => {
    if (!r.ok) throw new Error(`tor archive listing ${r.status}`)
    return r.text()
  })
  const versions = [...listing.matchAll(/href="(\d+\.\d+\.\d+)\//g)].map((m) => m[1])
  if (!versions.length) throw new Error("could not find a Tor version in the archive listing")
  const latest = versions.sort((a, b) => {
    const pa = a.split(".").map(Number)
    const pb = b.split(".").map(Number)
    for (let i = 0; i < 3; i += 1) if (pa[i] !== pb[i]) return pb[i] - pa[i]
    return 0
  })[0]
  const name = `${torAsset()}-${latest}.tar.gz`
  const url = `${TOR_DIST_URL}${latest}/${name}`
  const res = await fetch(url, { signal: AbortSignal.timeout(180_000) })
  if (!res.ok) throw new Error(`${name} → ${res.status}`)
  const entries = unpackTarGz(Buffer.from(await res.arrayBuffer()))
  if (!entries.length) throw new Error(`${name} contained no files`)
  fs.mkdirSync(toolsDir, { recursive: true })
  for (const entry of entries) {
    const dest = path.join(toolsDir, entry.name)
    const root = path.resolve(toolsDir)
    if (!path.resolve(dest).startsWith(root + path.sep)) continue
    fs.mkdirSync(path.dirname(dest), { recursive: true })
    fs.writeFileSync(dest, entry.data, { mode: 0o755 })
  }
  const located = findTorUnder(toolsDir)
  if (located) {
    try {
      fs.chmodSync(located, 0o755)
    } catch {}
  }
  log(`tor: ${latest} unpacked`)
}

// ---------------------------------------------------------------------------
// tor control protocol (just enough of it)
// ---------------------------------------------------------------------------

/**
 * A line-oriented client for tor's control port.
 *
 * CookieAuthentication is deliberate: the cookie file is readable by the same
 * user that started tor, so `AUTHENTICATE <hex>` is all the auth this needs.
 * SAFECOOKIE would mean reimplementing the challenge/HMAC handshake for no
 * gain on a loopback port.
 */
function createControl({ port, cookiePath, host = "127.0.0.1", timeoutMs = 10_000 }) {
  let socket = null
  let buffer = ""
  let pending = null
  let closed = false

  const settle = (fn, arg) => {
    const waiter = pending
    pending = null
    if (waiter) fn === "ok" ? waiter.resolve(arg) : waiter.reject(arg)
  }

  function pump() {
    // Replies are `250-` continuation lines terminated by `250 ` (or `250 OK`).
    const lines = buffer.split(/\r?\n/)
    buffer = lines.pop() ?? ""
    for (const line of lines) {
      if (!pending) continue
      if (/^(250|251)[- ]/.test(line)) {
        pending.lines.push(line.slice(4))
        if (/^(250|251) /.test(line)) settle("ok", pending.lines)
      } else if (/^[45]\d\d[- ]/.test(line)) {
        pending.lines.push(line)
        if (/^[45]\d\d /.test(line)) settle("err", Object.assign(new Error(line), { reply: pending.lines }))
      } else if (line === "650 OK" || line.startsWith("650 ")) {
        // async event: consumed, never a reply to a command
        continue
      }
    }
  }

  function connect() {
    // A lane's bootstrap retries this while tor is still opening its listener.
    // An earlier refused socket must not poison the connection that eventually
    // succeeds, so every handler below ignores sockets that are not the current
    // one and a successful connect clears the closed flag.
    if (socket && !closed) return Promise.resolve()
    return new Promise((resolve, reject) => {
      const sock = net.createConnection({ host, port })
      const timer = setTimeout(() => {
        sock.destroy()
        reject(new Error("control port timeout"))
      }, timeoutMs)
      sock.once("connect", () => {
        clearTimeout(timer)
        socket = sock
        closed = false
        buffer = ""
        resolve()
      })
      sock.once("error", (err) => {
        clearTimeout(timer)
        if (sock === socket) socket = null
        reject(err)
      })
      sock.on("data", (chunk) => {
        if (sock !== socket) return
        buffer += chunk.toString("utf8")
        pump()
      })
      sock.on("close", () => {
        if (sock !== socket) return
        socket = null
        closed = true
        if (pending) settle("err", new Error("control connection closed"))
      })
    })
  }

  function cmd(text) {
    if (closed || !socket) return Promise.reject(new Error("control connection closed"))
    return new Promise((resolve, reject) => {
      if (pending) {
        reject(new Error("control protocol: one command at a time"))
        return
      }
      pending = { resolve, reject, lines: [] }
      socket.write(`${text}\r\n`)
    })
  }

  async function authenticate() {
    const cookie = fs.readFileSync(cookiePath)
    await cmd(`AUTHENTICATE ${cookie.toString("hex")}`)
  }

  return {
    connect,
    authenticate,
    cmd,
    close() {
      closed = true
      try {
        socket?.end()
      } catch {}
      socket = null
    },
    get isOpen() {
      return Boolean(socket) && !closed
    },
  }
}

// ---------------------------------------------------------------------------
// one lane
// ---------------------------------------------------------------------------

class Lane {
  constructor(index, opts) {
    this.index = index
    this.dir = path.join(opts.dataDir, `lane-${index}`)
    this.torBinary = opts.torBinary
    this.strictNodes = opts.strictNodes
    this.maxCircuitDirtiness = opts.maxCircuitDirtiness
    this.proc = null
    this.tunnelPort = 0
    this.controlPort = 0
    this.control = null
    this.fingerprint = ""
    this.nickname = ""
    this.country = ""
    this.exitIp = ""
    this.state = "cold" // cold | booting | hot | benched | dead
    this.note = ""
    this.active = 0
    this.requests = 0
    this.errors = 0
    this.ridingSince = 0
    this.identity = null
    this.movedAt = 0
    // Nothing may move this lane's exit until a delivered body has had time to
    // finish streaming (see sweep()).
    this.busyUntil = 0
  }

  get proxyUrl() {
    return `http://127.0.0.1:${this.tunnelPort}`
  }

  get label() {
    return `lane ${this.index} {${this.country || "??"}}`
  }

  short() {
    return this.fingerprint ? this.fingerprint.slice(0, 8) : "-"
  }
}

// ---------------------------------------------------------------------------
// the lane manager
// ---------------------------------------------------------------------------

/**
 * @param {object} opts
 * @param {object} opts.config       the proxy's live config object (read, never written)
 * @param {(msg: string) => void} [opts.log]
 * @param {() => {session: string, project: string}} [opts.mintIdentity]
 * @param {() => {b3?: string, traceparent?: string}} [opts.mintTrace]  fresh trace identity for per-attempt rotation
 * @param {number} [opts.basePort]   first port a lane may use (tunnel/control pairs)
 */
export function createLanes(opts) {
  const config = opts.config
  const log = opts.log ?? (() => {})
  const mint =
    opts.mintIdentity ??
    (() => ({
      session: `ses_${randomBytes(19).toString("hex").slice(0, 32)}`,
      project: randomBytes(20).toString("hex"),
    }))
  // A wholly fresh trace identity per attempt. Absent by default: the proxy's
  // own trace headers (one stable per-process root, like the CLI) ride through.
  // `torRotateIdentity` supplies this so each attempt can present a brand-new
  // process identity instead of sharing the proxy's b3/traceparent root.
  const mintTrace = opts.mintTrace ?? (() => ({}))
  const now = opts.now ?? (() => Date.now())
  const basePort = opts.basePort ?? 19050

  const dataDir = config.torDataDir || path.join(os.tmpdir(), "zen-proxy-tor")
  const statePath = path.join(dataDir, "tor-ledger.json")
  const ledger = new Ledger(statePath, now)
  const lanes = []
  let started = false
  let starting = null
  let sweepTimer = null
  let lastError = ""
  // A failed boot is not retried on the next request. Ten lanes' worth of
  // discovery and download attempts per model call would turn a missing tor
  // into a denial of service on the proxy itself.
  let retryAt = 0
  let consensus = { at: 0, byCountry: new Map() }
  let torBinary = ""
  let served = 0
  let lastRace = null
  // Sticky mode's current lane. -1 means "pick one"; a refused exit clears it
  // so the next hot lane takes over.
  let pinnedIndex = -1

  const laneCount = () => Math.max(1, Math.min(64, Number(config.torLanes) || 10))
  const raceWidth = () => Math.max(1, Math.min(64, Number(config.torRaceWidth) || 5))

  function addLog(msg) {
    lastError = msg
    log(msg)
  }

  // -------------------------------------------------------------------------
  // exits
  // -------------------------------------------------------------------------

  async function loadConsensus() {
    if (consensus.at && now() - consensus.at < CONSENSUS_TTL_MS) return consensus
    const { byCountry } = await discoverExits()
    consensus = { at: now(), byCountry }
    return consensus
  }

  function countries() {
    const primary = splitCodes(config.torCountries)
    const fallback = splitCodes(config.torFallbackCountries)
    const preferred = splitCodes(config.torPreferredCountries)
    return {
      primary: primary.length ? primary : DEFAULT_COUNTRIES,
      fallback,
      preferred,
    }
  }

  function splitCodes(value) {
    if (Array.isArray(value)) {
      return value.map((c) => String(c).trim().toLowerCase()).filter((c) => /^[a-z]{2}$/.test(c))
    }
    return String(value || "")
      .split(",")
      .map((c) => c.trim().toLowerCase())
      .filter((c) => /^[a-z]{2}$/.test(c))
  }

  /**
   * Pick a fresh, distinct exit for a lane.
   *
   * lingling prefers freshness over bandwidth deliberately: the busiest relays
   * are the most shared, so they are also the ones whose daily 200 someone else
   * has already spent. Countries with no headroom fall through to the fallback
   * pool, then to the primary pool, then to letting tor choose.
   */
  function pickExit(country, taken) {
    const { byCountry } = consensus
    const usable = (cc) =>
      (byCountry.get(cc) || []).filter(
        (relay) => !taken.has(relay.fingerprint) && !ledger.limited(relay.fingerprint),
      )
    const pools = countries()
    // The explicit hint (a lane's old country) first, then the preferred pool,
    // then the main list and its fallback — lingling's boot order, kept.
    const order = country
      ? [country, ...pools.preferred, ...pools.primary, ...pools.fallback]
      : [...pools.preferred, ...pools.primary, ...pools.fallback]
    const seen = new Set()
    // Collect candidates from every country, not just the first one with a
    // relay: lanes spread across the pool instead of piling onto one country.
    const all = []
    for (const cc of order) {
      if (seen.has(cc)) continue
      seen.add(cc)
      for (const relay of usable(cc)) all.push({ relay, country: cc })
    }
    if (!all.length) return null
    // Least-ridden first: a relay this session has never touched beats one it
    // left ten minutes ago, and among equals the alphabetical order keeps the
    // pick reproducible.
    all.sort((a, b) => {
      const ua = ledger.usageFor(a.relay.fingerprint).requests
      const ub = ledger.usageFor(b.relay.fingerprint).requests
      if (ua !== ub) return ua - ub
      return a.relay.fingerprint.localeCompare(b.relay.fingerprint)
    })
    // A uniform pick among the least-used tier: fresh relays across many
    // countries get an even chance, so the fleet does not crowd the most common
    // exit pool (the busiest relays are the most shared, hence the most spent).
    const min = ledger.usageFor(all[0].relay.fingerprint).requests
    const fresh = all.filter((x) => ledger.usageFor(x.relay.fingerprint).requests === min)
    const chosen = fresh[Math.floor(Math.random() * fresh.length)]
    return { ...chosen.relay, country: chosen.country }
  }

  // -------------------------------------------------------------------------
  // tor process lifecycle
  // -------------------------------------------------------------------------

  function portFree(port) {
    return new Promise((resolve) => {
      const probe = net.createServer()
      probe.once("error", () => resolve(false))
      probe.once("listening", () => probe.close(() => resolve(true)))
      probe.listen(port, "127.0.0.1")
    })
  }

  async function allocatePorts(index) {
    // Two per lane so a lane's pair is predictable in logs; scan forward when
    // something else holds the slot rather than failing the whole boot.
    for (let slot = 0; slot < 400; slot += 1) {
      const tunnel = basePort + (index + slot) * 2
      const control = tunnel + 1
      if ((await portFree(tunnel)) && (await portFree(control))) return { tunnel, control }
    }
    throw new Error("no free loopback port pair for a tor lane")
  }

  function writeTorrc(lane) {
    // Forward slashes are tor's portable spelling; quotes are what makes a
    // Windows profile directory with a space ("C:\Users\John Doe") a single
    // argument instead of two.
    const forward = (p) => `"${String(p).replace(/\\/g, "/")}"`
    fs.mkdirSync(lane.dir, { recursive: true })
    const geo = geoipFor(lane.torBinary)
    const exitLine = lane.fingerprint ? [`ExitNodes $${lane.fingerprint}`, `StrictNodes ${lane.strictNodes ? 1 : 0}`] : []
    const torrc = [
      `DataDirectory ${forward(lane.dir)}`,
      // SOCKS off: every consumer here is Bun's fetch, which refuses socks5.
      "SocksPort 0",
      `HTTPTunnelPort 127.0.0.1:${lane.tunnelPort}`,
      `ControlPort 127.0.0.1:${lane.controlPort}`,
      "CookieAuthentication 1",
      `CookieAuthFile ${forward(path.join(lane.dir, "control_auth_cookie"))}`,
      `MaxCircuitDirtiness ${lane.maxCircuitDirtiness}`,
      "ConnectionPadding 0",
      "ClientOnly 1",
      "AvoidDiskWrites 1",
      ...(geo.geoip ? [`GeoIPFile ${forward(geo.geoip)}`] : []),
      ...(geo.geoip6 ? [`GeoIPv6File ${forward(geo.geoip6)}`] : []),
      // No quotes here: tor's Log parser keeps them as part of the filename and
      // then fails to open it. The lane's cwd is its directory, so a bare
      // filename is both valid and space-safe.
      "Log notice file tor.log",
      ...exitLine,
      "",
    ].join("\n")
    fs.writeFileSync(path.join(lane.dir, "torrc"), torrc)
    return path.join(lane.dir, "torrc")
  }

  function spawnTor(lane, torrcPath) {
    const child = spawn(lane.torBinary, ["-f", torrcPath], {
      cwd: lane.dir,
      stdio: ["ignore", "ignore", "pipe"],
      windowsHide: true,
    })
    child.stderr?.on("data", (chunk) => {
      const text = chunk.toString("utf8").trim()
      if (text) log(`tor ${lane.index}: ${text.split(/\r?\n/)[0]}`)
    })
    child.on("exit", (code, signal) => {
      lane.proc = null
      if (lane.state !== "dead") {
        lane.state = "dead"
        lane.note = `tor exited (${signal || code})`
        log(`${lane.label} tor exited (${signal || code}) — the sweep will re-cook it`)
      }
    })
    lane.proc = child
    return child
  }

  async function waitFor(predicate, { timeoutMs = 60_000, intervalMs = 250, what = "condition" } = {}) {
    const deadline = now() + timeoutMs
    for (;;) {
      if (await predicate()) return true
      if (now() > deadline) throw new Error(`timed out waiting for ${what}`)
      await new Promise((r) => setTimeout(r, intervalMs))
    }
  }

  /** The last thing tor complained about, so a dead lane explains itself. */
  function lastTorError(lane) {
    try {
      const lines = fs
        .readFileSync(path.join(lane.dir, "tor.log"), "utf8")
        .trim()
        .split(/\r?\n/)
        .filter((line) => /\[(err|warn)\]/.test(line))
      if (!lines.length) return ""
      return lines[lines.length - 1].replace(/^.*?\[(?:err|warn)\]\s*/, "")
    } catch {
      return ""
    }
  }

  async function bootstrap(lane) {
    const cookiePath = path.join(lane.dir, "control_auth_cookie")
    await waitFor(
      () => {
        if (!lane.proc && fs.existsSync(path.join(lane.dir, "tor.log"))) {
          // tor died before it ever opened a control port. Its own words are far
          // more useful than "control connection closed" — a tor too old for the
          // consensus says exactly that.
          throw new Error(lastTorError(lane) || "tor exited during bootstrap")
        }
        return fs.existsSync(cookiePath)
      },
      { timeoutMs: 30_000, what: "tor's control cookie" },
    )
    const control = createControl({ port: lane.controlPort, cookiePath })
    await waitFor(
      () => {
        if (!lane.proc) throw new Error(lastTorError(lane) || "tor exited before its control port opened")
        return control.connect().then(() => true, () => false)
      },
      { timeoutMs: 30_000, what: "tor's control port" },
    )
    await control.authenticate()
    lane.control = control
    // Bootstrap is the slow part on a cold cache (a few minutes, once). 100 is
    // the only phase that means the tunnel can carry traffic.
    await waitFor(
      async () => {
        const [line] = await control.cmd("GETINFO status/bootstrap-phase")
        return /PROGRESS=100/.test(line || "")
      },
      { timeoutMs: 240_000, intervalMs: 500, what: "tor bootstrap" },
    )
    lane.state = "hot"
  }

  /** Through the lane's own tunnel: proves the exit works and names its IP. */
  async function probeExit(lane, { signal } = {}) {
    if (!config.torProof) return ""
    try {
      const res = await fetch(TOR_CHECK, {
        proxy: lane.proxyUrl,
        signal: signal ?? AbortSignal.timeout(20_000),
        headers: { "user-agent": config.ua },
      })
      if (!res.ok) return ""
      const parsed = await res.json()
      const ip = String(parsed?.IP || "")
      if (ip) lane.exitIp = ip
      return ip
    } catch {
      return ""
    }
  }

  function mintForLane(lane) {
    const pair = mint()
    lane.identity = { session: pair.session, project: pair.project, at: now() }
    return lane.identity
  }

  async function bootLane(lane, countryHint) {
    lane.state = "booting"
    lane.note = ""
    const taken = new Set(lanes.filter((l) => l !== lane && l.fingerprint).map((l) => l.fingerprint))
    // A re-cook must not land on the exit it is leaving: that exit is the reason
    // the lane is being rebuilt (or was written off a moment ago).
    if (lane.fingerprint) taken.add(lane.fingerprint)
    await loadConsensus()
    const pick = pickExit(countryHint, taken)
    lane.fingerprint = pick?.fingerprint ?? ""
    lane.nickname = pick?.nickname ?? ""
    lane.country = pick?.country ?? ""
    if (!pick) lane.note = "no fresh exit found — letting tor choose"
    const { tunnel, control } = await allocatePorts(lane.index)
    lane.tunnelPort = tunnel
    lane.controlPort = control
    const torrc = writeTorrc(lane)
    spawnTor(lane, torrc)
    await bootstrap(lane)
    await probeExit(lane)
    mintForLane(lane)
    lane.ridingSince = now()
    lane.requests = 0
    lane.state = "hot"
    log(
      `${lane.label} hot${lane.exitIp ? ` at ${lane.exitIp}` : ""}${lane.fingerprint ? ` (${lane.short()})` : ""}`,
    )
    return lane
  }

  /**
   * Move a lane to another exit without a restart.
   *
   * SETCONF + SIGNAL NEWNYM is what lingling does through stem; re-cooking the
   * process is only the fallback, because a cold bootstrap costs minutes.
   */
  async function moveLane(lane, reason = "") {
    if (lane.active > 0) return false // a copy is still on the wire
    const taken = new Set(lanes.filter((l) => l !== lane && l.fingerprint).map((l) => l.fingerprint))
    // "Move" has to mean move: the exit being left is never the answer to why
    // the lane is leaving it (soft cap, hold window, or a verdict).
    if (lane.fingerprint) taken.add(lane.fingerprint)
    if (!lane.control?.isOpen) {
      // No control channel: the only way off this exit is a fresh process.
      await recook(lane, reason)
      return true
    }
    await loadConsensus()
    const pick = pickExit("", taken)
    if (!pick) {
      await recook(lane, reason || "no fresh exit left")
      return true
    }
    try {
      await lane.control.cmd(`SETCONF ExitNodes=$${pick.fingerprint} StrictNodes=1`)
      await lane.control.cmd("SIGNAL NEWNYM")
    } catch (err) {
      log(`${lane.label} could not move (${err.message}) — re-cooking`)
      await recook(lane, reason)
      return true
    }
    lane.fingerprint = pick.fingerprint
    lane.nickname = pick.nickname
    lane.country = pick.country
    lane.exitIp = ""
    lane.requests = 0
    lane.ridingSince = now()
    lane.movedAt = now()
    ledger.forget(pick.fingerprint)
    // The pair turns over with the address. One identity, one address — never
    // one session seen from the whole fleet.
    mintForLane(lane)
    await probeExit(lane)
    log(`${lane.label} moved${lane.exitIp ? ` to ${lane.exitIp}` : ""}${reason ? ` (${reason})` : ""}`)
    return true
  }

  async function recook(lane, reason = "") {
    stopLane(lane)
    try {
      await bootLane(lane)
      log(`${lane.label} re-cooked${reason ? ` (${reason})` : ""}`)
      return true
    } catch (err) {
      lane.state = "dead"
      lane.note = err.message
      log(`${lane.label} would not come up: ${err.message}`)
      return false
    }
  }

  function stopLane(lane) {
    try {
      lane.control?.close()
    } catch {}
    lane.control = null
    if (lane.proc) {
      const child = lane.proc
      lane.proc = null
      lane.state = "cold"
      try {
        child.kill()
      } catch {}
    }
  }

  // -------------------------------------------------------------------------
  // starting and sweeping
  // -------------------------------------------------------------------------

  async function start() {
    if (started) return status()
    if (starting) return starting
    if (now() < retryAt) return status()
    starting = (async () => {
      // Node's fetch accepts a `proxy` option and then ignores it: every copy
      // would leave from the same address, spend the same allowance, and change
      // nothing. Refusing loudly is the only honest outcome.
      if (typeof Bun === "undefined") {
        lastError = "tor lanes need Bun — Node's fetch ignores the per-lane proxy"
        log(`tor: ${lastError}; lanes stay off — requests fail rather than ride your own address`)
        retryAt = now() + 3600_000
        starting = null
        return status()
      }
      const count = laneCount()
      const mode = singleMode() ? "sticky, one exit at a time" : `wave width ${raceWidth()}`
      log(`tor: starting ${count} lane(s), ${mode}${config.torDataDir ? "" : ` (state in ${dataDir})`}`)
      try {
        torBinary = await ensureTorBinary({
          dataDir,
          override: config.torBinary || "",
          download: config.torDownload !== false,
          log,
        })
        log(`tor: using ${torBinary}`)
      } catch (err) {
        lastError = `no usable tor: ${err.message}`
        log(`tor: ${lastError} — lanes stay off — requests fail rather than ride your own address`)
        retryAt = now() + 60_000
        starting = null
        return status()
      }
      try {
        await loadConsensus()
      } catch (err) {
        lastError = `exit discovery failed: ${err.message}`
        log(`tor: ${lastError} — lanes stay off — requests fail rather than ride your own address`)
        retryAt = now() + 60_000
        starting = null
        return status()
      }
      // First lane eagerly (the wave needs something hot), the rest in the
      // background: a cold bootstrap is minutes and nobody wants to stare at it.
      const first = new Lane(0, laneOpts())
      lanes.push(first)
      try {
        await bootLane(first)
      } catch (err) {
        lastError = err.message
        first.state = "dead"
        first.note = err.message
        log(`tor: lane 0 did not come up (${err.message})`)
      }
      for (let i = 1; i < count; i += 1) lanes.push(new Lane(i, laneOpts()))
      const rest = lanes.slice(1)
      if (rest.length) {
        (async () => {
          for (const lane of rest) {
            try {
              await bootLane(lane)
            } catch (err) {
              lane.state = "dead"
              lane.note = err.message
              log(`${lane.label} did not come up: ${err.message}`)
            }
          }
          log(`tor: ${hotLanes().length}/${lanes.length} lanes hot`)
        })().catch(() => {})
      }
      started = true
      schedule()
      return status()
    })()
    return starting
  }

  function laneOpts() {
    return {
      dataDir,
      torBinary: torBinary || config.torBinary || "tor",
      strictNodes: config.torStrictNodes !== false,
      maxCircuitDirtiness: Math.max(60, Number(config.torMaxCircuitDirtiness) || 600),
    }
  }

  function hotLanes() {
    return lanes.filter((lane) => lane.state === "hot" && lane.tunnelPort && !ledger.limited(lane.fingerprint))
  }

  function schedule() {
    if (sweepTimer) return
    const every = Math.max(5, Number(config.torSweepS) || 20) * 1000
    sweepTimer = setInterval(() => {
      if (!started) return
      try {
        sweep()
      } catch (err) {
        log(`tor sweep: ${err.message}`)
      }
    }, every)
    sweepTimer.unref?.()
  }

  /**
   * Leave an exit before it is spent.
   *
   * An exit's daily allowance belongs to whoever reaches it first, and the only
   * way to find out someone else got there is to be refused — so lanes leave
   * early instead: after `torExitSoftCap` requests, or after `torExitHoldS`
   * seconds riding it (other people's requests through that address show up in
   * no ledger we keep).
   */
  // Callable on its own (the tests do), not only from the timer. `moveLane` can
  // be overridden so the selection logic is testable without a tor beside it.
  async function sweep({ moveLane: relocate } = {}) {
    const softCap = Math.max(1, Number(config.torExitSoftCap) || Math.floor(EXIT_CAP / 2))
    const holdS = Math.max(30, Number(config.torExitHoldS) || 600)
    const maxMoves = Math.max(1, Number(config.torSweepMoves) || 3)
    const candidates = []
    for (const lane of lanes) {
      if (lane.state === "dead") {
        candidates.push({ lane, why: "lane was dead" })
        continue
      }
      // A lane that just handed a reply to the client is still streaming it:
      // moving its exit now would cut an answer that is already half-delivered.
      if (lane.state !== "hot" || lane.active > 0 || (lane.busyUntil || 0) > now()) continue
      if (ledger.limited(lane.fingerprint)) {
        candidates.push({ lane, why: `exit is ${ledger.reasonFor(lane.fingerprint)}` })
        continue
      }
      // Sticky mode keeps a working exit on purpose: neither the soft cap nor
      // the hold window moves it. Only a refusal (above) or a dead lane does.
      if (singleMode()) continue
      if (lane.requests >= softCap) candidates.push({ lane, why: `${lane.requests} requests on this exit` })
      else if (lane.ridingSince && now() - lane.ridingSince > holdS * 1000) {
        candidates.push({ lane, why: `riding this exit ${Math.round((now() - lane.ridingSince) / 1000)}s` })
      }
    }
    // Longest-riding first.
    candidates.sort((a, b) => (a.lane.ridingSince || 0) - (b.lane.ridingSince || 0))
    let moved = 0
    for (const { lane, why } of candidates) {
      if (moved >= maxMoves) break
      const ok = relocate
        ? await relocate(lane, why)
        : lane.state === "dead"
          ? await recook(lane, why)
          : await moveLane(lane, why)
      if (ok) moved += 1
    }
    if (moved) log(`tor sweep: moved ${moved} lane(s)`)
  }

  // -------------------------------------------------------------------------
  // the race
  // -------------------------------------------------------------------------

  function rotateIdentity() {
    return Boolean(config.torRotateIdentity)
  }

  function laneHeaders(lane, { rotate = false } = {}) {
    // Per-attempt rotation mints a brand-new session + project + trace root, so
    // a flagged identity never rides a fresh exit. Without it the lane's stable
    // pair is reused — cheaper, but a refused pair follows the lane everywhere.
    const identity = rotate ? mint() : (lane.identity ?? mintForLane(lane))
    const headers = {
      "x-opencode-session": identity.session,
      "x-opencode-session-id": identity.session,
      "x-session-affinity": identity.session,
      "x-session-id": identity.session,
      "x-opencode-project": identity.project,
    }
    if (rotate) Object.assign(headers, mintTrace())
    return headers
  }

  /** Stable lane for a caller-owned session: never fan one session across exits. */
  const stickyAssignments = new Map()
  function stickyLane(key) {
    const hot = hotLanes()
    if (!hot.length) return null
    const text = String(key || "")
    // A caller's own session is pinned to the lane it first met, not to
    // whatever the hash lands on after a sweep changed the pool's shape. A
    // session that hops exits is exactly the client the gate refuses.
    const remembered = stickyAssignments.get(text)
    if (remembered != null) {
      const lane = hot.find((l) => l.index === remembered)
      if (lane) return lane
    }
    let hash = 0
    for (let i = 0; i < text.length; i += 1) hash = (hash * 31 + text.charCodeAt(i)) >>> 0
    const lane = hot[hash % hot.length]
    stickyAssignments.set(text, lane.index)
    // The map is per-process and bounded: forget the oldest pins rather than
    // growing one entry per session id a caller ever sent.
    for (const oldest of stickyAssignments.keys()) {
      if (stickyAssignments.size <= 2000) break
      stickyAssignments.delete(oldest)
    }
    return lane
  }

  function pickWave(width) {
    const hot = hotLanes()
    if (!hot.length) return []
    // Least-loaded first, so no lane carries a wave the others could share.
    const ordered = [...hot].sort((a, b) => a.active - b.active || a.index - b.index)
    return ordered.slice(0, Math.min(width, ordered.length))
  }

  // -------------------------------------------------------------------------
  // sticky mode: one exit at a time
  // -------------------------------------------------------------------------

  /**
   * Sticky mode trades breadth for conservation. The race spends five exits'
   * allowances to get one answer; sticky mode keeps a single exit and rides it
   * until the gate refuses it. Only then does the next hot lane take over, so
   * the rest of the fleet stays unspent for later.
   */
  function singleMode() {
    return Boolean(config.torSticky)
  }

  /**
   * The one lane sticky mode is riding.
   *
   * Deliberately not "least loaded": two concurrent calls must share one exit,
   * not each take a different one. The pin survives across calls while the exit
   * is still welcome at the gate; a refusal clears it and the next hot lane
   * (lowest index) becomes the new pin.
   */
  function pickSingleLane() {
    const hot = hotLanes()
    if (!hot.length) return null
    const current = hot.find((lane) => lane.index === pinnedIndex)
    if (current) return current
    const next = [...hot].sort((a, b) => a.index - b.index)[0]
    pinnedIndex = next.index
    return next
  }

  /** Move one refused lane to a fresh exit, so a drained fleet refills. */
  async function rotateOne() {
    const lane = lanes.find(
      (l) => l.state === "hot" && !l.active && l.fingerprint && ledger.limited(l.fingerprint),
    )
    if (!lane) return false
    return moveLane(lane, `exit is ${ledger.reasonFor(lane.fingerprint)}`).catch(() => false)
  }

  async function copyFetch(lane, url, init, headers) {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(new Error("lane timeout")), Number(config.timeoutMs) || 120_000)
    timeout.unref?.()
    // The caller's wall (a stream's headers timeout) must still be able to cut
    // this copy, so the two signals are combined. AbortSignal.any landed after
    // Node 18, and this package still claims >=18, so it is feature-detected.
    const signal = init?.signal
      ? (AbortSignal.any ? AbortSignal.any([init.signal, controller.signal]) : init.signal)
      : controller.signal
    lane.active += 1
    try {
      const res = await fetch(url, { ...init, headers, proxy: lane.proxyUrl, signal })
      // Headers are here, so this copy is no longer "waiting": the timer only
      // exists to bound the wait for a first byte. Leaving it armed would abort
      // a winning stream mid-reply.
      clearTimeout(timeout)
      ledger.spend(lane.fingerprint)
      // The sweep's soft cap reads the lane's own count, not the ledger's: an
      // exit is left early after torExitSoftCap calls, and the ledger keeps its
      // own lifetime row for picking the least-ridden relay.
      lane.requests += 1
      // The grace window exists for a body that is still streaming to the
      // client. A refusal is a verdict, not a stream, so it is free to rotate
      // on the next sweep instead of sitting out the full grace.
      if (res.status === 200) lane.busyUntil = now() + (Number(config.torStreamGraceS) || 120) * 1000
      return { res, controller }
    } catch (err) {
      clearTimeout(timeout)
      throw err
    } finally {
      lane.active -= 1
    }
  }

  async function bookkeepLoser(result) {
    try {
      if (!result?.res || (result.res.status !== 429 && result.res.status !== 403)) return
      const { text, retry } = await readVerdict(result.res)
      const verdict = classifyFailure(result.res.status, text, retry, now())
      if (verdict.reason) {
        ledger.note(result.lane.fingerprint, verdict.reason, verdict.until)
        log(`${result.lane.label} ${result.res.status} ${verdict.reason} — moving it`)
      }
    } catch {
      // Aborted mid-read: the exit keeps its old record and earns a fresh
      // verdict on the next call. Nothing to do here.
    }
  }

  async function readVerdict(res) {
    let text = ""
    try {
      text = await res.clone().text()
    } catch {}
    return { text, retry: res.headers.get("retry-after") }
  }

  /**
   * One call, down one lane, kept until it is refused.
   *
   * The sticky-mode counterpart to the race: no copies, no fan-out. A refusal
   * charges the exit, moves the pin to the next hot lane and retries — bounded
   * by the same `torRetryMs` wall as the race. A caller-owned identity travels
   * untouched (`opts.identity === false`); an anonymous call carries the lane's
   * minted pair.
   */
  async function fetchSingle(url, init = {}, opts = {}) {
    const persist = Boolean(started)
    const retryMs = Number(opts.deadlineMs) || Number(config.torRetryMs) || Number(config.timeoutMs) || 120_000
    const deadline = now() + retryMs
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
    // Without a live fleet (tests, pre-start) one pass over the pool is enough:
    // a test must not hang waiting for a sweep that never runs.
    let attemptsLeft = persist ? Infinity : Math.max(1, lanes.length)
    let lastResponse = null
    let lastThrow = null

    while (persist ? now() < deadline : attemptsLeft-- > 0) {
      const lane = pickSingleLane()
      if (!lane) {
        if (!persist) break
        // Every exit is sitting out: rotate one back in and try it again.
        const rotated = await rotateOne()
        if (!rotated) await sleep(500)
        continue
      }
      const headers = {
        ...(init.headers || {}),
        ...(opts.headers || {}),
        ...(opts.identity === false ? {} : laneHeaders(lane, { rotate: rotateIdentity() })),
      }
      let res
      try {
        ;({ res } = await copyFetch(lane, url, init, headers))
      } catch (err) {
        // The caller's own wall cut the request: stop, and do not write the
        // lane off for an abort that came from our side of the wire.
        if (init?.signal?.aborted) throw err
        lastThrow = err
        ledger.note(lane.fingerprint, BLOCKED, now() + BLOCKED_COOLDOWN_MS)
        log(`${lane.label} ${err.message} — trying another exit`)
        pinnedIndex = -1
        continue
      }
      if (res.status === 200) {
        if (lastResponse) {
          try {
            await lastResponse.body?.cancel?.()
          } catch {}
        }
        served += 1
        lastRace = { at: now(), lanes: [lane.index], winner: lane.index, racers: 1 }
        ledger.noteOk(lane.fingerprint)
        return res
      }
      // Keep the newest refusal so the client still sees the far end's own words
      // when no exit can serve the call.
      if (lastResponse && lastResponse !== res) {
        try {
          await lastResponse.body?.cancel?.()
        } catch {}
      }
      lastResponse = res
      if (res.status === 429 || res.status === 403) {
        const { text, retry } = await readVerdict(res)
        const verdict = classifyFailure(res.status, text, retry, now())
        if (verdict.edge) {
          // The edge, not the exit: keep riding the same lane.
          log(`429 OPENCODE EDGE UNAVAILABLE -- not ${lane.label}`)
          continue
        }
        if (verdict.reason) {
          ledger.note(lane.fingerprint, verdict.reason, verdict.until)
          log(`${lane.label} ${res.status} ${verdict.reason} — moving to another exit`)
        }
        pinnedIndex = -1
        continue
      }
      if (res.status >= 500) {
        log(`${lane.label} ${res.status} — retrying on another exit`)
        pinnedIndex = -1
        continue
      }
      // Any other status (400, 404) is the caller's answer, not an exit problem.
      return res
    }

    if (lastResponse) return lastResponse
    throw lastThrow ?? new Error(lastError || "no lane could serve the call")
  }

  /**
   * One call, down a wave of lanes, first 200 wins.
   *
   * `opts.headers` is the head every copy carries; `opts.lanes` overrides the
   * width. Anything that is not a 200 is charged to the exit it came from and
   * retried on lanes that have not already answered for this call — walking the
   * pool twice, exactly like lingling, and only then handing the far end's own
   * words to the client.
   */
  async function fetchWithLanes(url, init = {}, opts = {}) {
    // Sticky mode applies to every caller, including one that brought its own
    // session: the whole point is that the proxy rides a single address, not a
    // fleet. A caller-owned identity is still left untouched (opts.identity).
    if (singleMode()) return fetchSingle(url, init, opts)

    const width = opts.lanes ?? raceWidth()
    // The old bound: walk the pool this many times before giving up. A live
    // fleet persists past it (below) until a lane wins or the caller's wall cuts
    // in — "keep trying exits until one works".
    const rounds = Math.max(1, Number(opts.rounds ?? config.torRounds) || 2)
    // Persistence means rotating refused exits and trying again, and it only
    // makes sense against a live fleet. Before start — and under the tests'
    // fake lanes — the bounded walk keeps a request from hanging forever.
    const persist = Boolean(started)
    const retryMs = Number(opts.deadlineMs) || Number(config.torRetryMs) || Number(config.timeoutMs) || 120_000
    const deadline = now() + (persist ? retryMs : rounds * (Number(config.timeoutMs) || 120_000))
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
    const sticky = opts.stickyKey ? stickyLane(opts.stickyKey) : null

    // Move refused lanes to fresh exits. `only` narrows it to the lanes a call
    // just charged; without it, every limited lane rotates. Returns whether
    // anything moved, so a caller can tell progress from a stall.
    async function rotateRefused(only = null) {
      const candidates = (only ?? lanes).filter(
        (lane) =>
          lane &&
          lane.state === "hot" &&
          !lane.active &&
          (lane.fingerprint ? ledger.limited(lane.fingerprint) : false),
      )
      if (!candidates.length) return false
      await Promise.all(
        candidates.map((lane) =>
          moveLane(lane, `exit is ${ledger.reasonFor(lane.fingerprint)}`).catch(() => false),
        ),
      )
      return true
    }

    if (opts.stickyKey) {
      // A caller that brought its own session gets one lane, never a fleet, and
      // never the device network. If that lane is spent (or not up yet), wait for
      // a healthy one and re-pin the session to it.
      let lane = sticky
      while (persist ? now() < deadline : true) {
        if (!lane) lane = stickyLane(opts.stickyKey)
        if (!lane) {
          if (!persist) return fetch(url, init) // tests / pre-start: old behaviour
          await sleep(1000)
          continue
        }
        const { res } = await copyFetch(lane, url, init, { ...(init.headers || {}), ...(opts.headers || {}) })
        if (res.status === 429 || res.status === 403) {
          // Charge the verdict even though there was no race: the next call then
          // hashes onto a lane that is still welcome at the gate.
          const { text, retry } = await readVerdict(res)
          const verdict = classifyFailure(res.status, text, retry, now())
          if (verdict.reason) {
            ledger.note(lane.fingerprint, verdict.reason, verdict.until)
            log(`${lane.label} ${res.status} ${verdict.reason} — ${persist ? "moving it" : "sitting it out"}`)
          }
          if (persist && now() < deadline) {
            try {
              await moveLane(lane, `exit is ${verdict.reason || "refused"}`)
            } catch {}
            lane = null
            continue
          }
        }
        return res
      }
      throw new Error("no tor lane could serve a sticky session in time")
    }

    let lastResponse = null
    let lastThrow = null
    const tried = new Set()
    let round = 0

    while (persist ? now() < deadline : round < rounds) {
      round += 1
      const wave = pickWave(width).filter((lane) => !tried.has(lane.index))
      if (!wave.length) {
        if (!persist) break
        // Nothing hot and un-tried: rotate the refused pool and keep going.
        tried.clear()
        const rotated = await rotateRefused()
        if (!rotated) await sleep(1000)
        continue
      }
      // Each copy gets its own cut switch, so a loser can be hung up the moment
      // somebody else wins — a losing copy downloading a whole answer spends an
      // exit's daily 200 for nothing.
      const cuts = []
      const settledResults = []
      const attempts = wave.map((lane) => {
        tried.add(lane.index)
        const cut = new AbortController()
        cuts.push(cut)
        const headers = {
          ...(init.headers || {}),
          ...(opts.headers || {}),
          ...(opts.identity === false ? {} : laneHeaders(lane, { rotate: rotateIdentity() })),
        }
        const copyInit = init?.signal
          ? { ...init, signal: AbortSignal.any ? AbortSignal.any([init.signal, cut.signal]) : cut.signal }
          : { ...init, signal: cut.signal }
        const pending = copyFetch(lane, url, copyInit, headers).then(
          ({ res, controller }) => {
            const result = { lane, res, controller, cut }
            settledResults.push(result)
            return result
          },
          (err) => ({ lane, error: err, cut }),
        )
        return pending
      })

      let winner = null
      const losers = []
      await new Promise((resolve) => {
        let settled = 0
        for (const attempt of attempts) {
          attempt.then(async (result) => {
            settled += 1
            if (result.error) {
              lastThrow = result.error
              // A copy that never got an answer is the exit's problem until
              // proven otherwise: write the address off briefly and let the
              // sweep move the lane. The lane itself stays hot.
              ledger.note(result.lane.fingerprint, BLOCKED, now() + BLOCKED_COOLDOWN_MS)
              if (settled === attempts.length) resolve()
              return
            }
            if (!winner && result.res.status === 200) {
              winner = result
              resolve()
              return
            }
            losers.push(result)
            if (settled === attempts.length) resolve()
          })
        }
      })

      if (winner) {
        served += 1
        lastRace = { at: now(), lanes: wave.map((l) => l.index), winner: winner.lane.index, racers: attempts.length }
        ledger.noteOk(winner.lane.fingerprint)
        // A losing lane's 429 is the pool working, not the call failing: it has
        // to reach the ledger too, or the next call keeps racing an exit that is
        // already spent. Bodies are read before the cut, and never awaited — the
        // client's answer is already on its way.
        for (const result of settledResults) {
          if (result === winner) continue
          void bookkeepLoser(result)
        }
        // Everyone else is cut before they say a word. The beat exists only so
        // a small 429 body that is already arriving can be read and charged.
        const cutDelay = setTimeout(() => {
          for (const cut of cuts) {
            if (cut !== winner.cut) {
              try {
                cut.abort()
              } catch {}
            }
          }
        }, 120)
        cutDelay.unref?.()
        return winner.res
      }

      // Nothing 200'd: charge each exit its own verdict, then walk the pool.
      for (const result of losers) {
        if (result.res?.status === 429 || result.res?.status === 403) {
          const { text, retry } = await readVerdict(result.res)
          const verdict = classifyFailure(result.res.status, text, retry, now())
          if (verdict.edge) {
            log(`429 OPENCODE EDGE UNAVAILABLE -- not ${result.lane.label}`)
          } else if (verdict.reason) {
            ledger.note(result.lane.fingerprint, verdict.reason, verdict.until)
            log(`${result.lane.label} ${result.res.status} ${verdict.reason} — exit out until ${new Date(verdict.until).toISOString().slice(11, 16)}Z`)
          }
        } else if (result.res && result.res.status >= 500) {
          // The far end's bad moments reach a different edge through another
          // exit, so they are retried like a 429 and never charged to the exit.
          log(`${result.lane.label} ${result.res.status} — retrying on another exit`)
        }
        lastResponse = result.res ?? lastResponse
      }
      // Losers we did not return are dropped so their sockets do not leak.
      for (const result of losers) {
        if (result.res !== lastResponse) {
          try {
            await result.res?.body?.cancel?.()
          } catch {}
        }
      }
      if (persist) {
        // Rotate the refused exits so the next pass starts from fresh addresses.
        for (const result of losers) tried.delete(result.lane.index)
        await rotateRefused(losers.map((r) => r.lane))
      }
    }

    if (lastResponse) return lastResponse
    throw lastThrow ?? new Error(lastError || "no lane could serve the call")
  }

  // -------------------------------------------------------------------------
  // status & shutdown
  // -------------------------------------------------------------------------

  function status() {
    return {
      enabled: Boolean(config.torEnabled),
      started,
      laneCount: lanes.length,
      hot: hotLanes().length,
      sticky: singleMode(),
      pinned: pinnedIndex,
      rotateIdentity: rotateIdentity(),
      width: singleMode() ? 1 : raceWidth(),
      error: lastError,
      served,
      lastRace,
      dataDir,
      torBinary,
      lanes: lanes.map((lane) => ({
        index: lane.index,
        state: lane.state,
        country: lane.country,
        fingerprint: lane.fingerprint,
        nickname: lane.nickname,
        exitIp: lane.exitIp,
        requests: lane.requests,
        active: lane.active,
        ridingS: lane.ridingSince ? Math.round((now() - lane.ridingSince) / 1000) : 0,
        identity: lane.identity ? `${lane.identity.session.slice(0, 10)}…` : "",
        limited: ledger.reasonFor(lane.fingerprint),
        note: lane.note,
      })),
      ledger: ledger.summary(),
    }
  }

  function stop() {
    if (sweepTimer) clearInterval(sweepTimer)
    sweepTimer = null
    for (const lane of lanes) stopLane(lane)
    // A later start() builds a fresh fleet; leaving the old lane objects behind
    // would duplicate every index and race two tor processes for one port pair.
    lanes.length = 0
    started = false
    starting = null
    retryAt = 0
    pinnedIndex = -1
    ledger.save()
  }

  return {
    start,
    stop,
    status,
    fetch: fetchWithLanes,
    moveLane,
    sweep,
    get started() {
      return started
    },
    get hot() {
      return hotLanes().length
    },
    ledger,
    lanes,
    // exposed for the tests and for `--tor-demo`
    classifyFailure,
    pickWave,
    pickSingleLane,
  }
}

// Stop the lanes when the process does, however it goes. tor children are not
// detached, so on POSIX they die with us; on Windows a killed parent leaves
// them running unless we say otherwise, and a stray tor per crashed session is
// how a machine ends up with a dozen of them.
export function installExitHandler(manager) {
  const bye = () => {
    try {
      manager.stop()
    } catch {}
  }
  process.once("exit", bye)
  for (const sig of ["SIGINT", "SIGTERM"]) {
    process.once(sig, () => {
      bye()
      process.exit(0)
    })
  }
  return bye
}
