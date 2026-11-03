// Cloudflare WARP as a single upstream transport for zen-proxy.
//
// The WARP client's `proxy` mode leaves the device's normal routing alone and
// exposes a local HTTP proxy on 127.0.0.1:<port>. Pointing Bun's fetch at that
// proxy sends only zen-proxy's upstream calls through the tunnel; everything
// else on the machine keeps using the ordinary network. Bun terminates TLS
// itself (the proxy is CONNECT), so the request fingerprint is unchanged.
//
// This is deliberately not a lane fleet like tor.mjs. One WARP registration is
// one tunnel and the client can only hold one at a time, so racing copies would
// leave from the same address and spend the same allowance. The identity
// roster is what spreads usage across sessions; WARP just keeps that traffic
// off the device's own address.
//
// Two promises this file keeps:
//
//   * The proxy is only used after Cloudflare's trace endpoint says
//     `warp=on`. A stale port, a stopped client, or a different proxy on that
//     port is a failure, never a quiet fall back to the device network.
//   * Managed mode restores the client's previous mode and connection on stop,
//     so enabling this for a run does not leave the whole machine on proxy mode.

import { execFile, execFileSync } from "node:child_process"
import fs from "node:fs"
import path from "node:path"

export const WARP_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
export const DEFAULT_WARP_PROXY = "http://127.0.0.1:40000"

const DEFAULT_PROBE_MS = 60_000
const CONNECT_TIMEOUT_MS = 30_000
const RETRY_MS = 30_000
const NODE_RETRY_MS = 3600_000

/** `http://host:port`, with credentials kept and any path dropped. */
export function normalizeProxyUrl(value) {
  const raw = String(value ?? "").trim() || DEFAULT_WARP_PROXY
  let url
  try {
    url = new URL(raw)
  } catch {
    throw new Error(`warp: not a proxy URL: ${raw}`)
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`warp: proxy must be http:// or https:// (got ${url.protocol})`)
  }
  const auth = url.username ? `${url.username}${url.password ? ":" + url.password : ""}@` : ""
  return `${url.protocol}//${auth}${url.host}`
}

/**
 * The port managed mode should tell `warp-cli proxy port`, or 0 when the
 * configured endpoint is not a local one (a remote proxy is external-only).
 */
export function proxyPort(value) {
  let url
  try {
    url = new URL(normalizeProxyUrl(value))
  } catch {
    return 0
  }
  const host = url.hostname.replace(/^\[|\]$/g, "")
  if (!["127.0.0.1", "localhost", "::1"].includes(host)) return 0
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80))
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : 0
}

/** The `key=value` lines Cloudflare's trace endpoint returns. */
export function parseTrace(text) {
  const out = {}
  for (const line of String(text ?? "").split(/\r?\n/)) {
    const at = line.indexOf("=")
    if (at <= 0) continue
    const key = line.slice(0, at).trim()
    if (key === "ip" || key === "warp" || key === "loc" || key === "colo") {
      out[key] = line.slice(at + 1).trim()
    }
  }
  return out
}

/** `settings list` prints `(default) Mode: Warp`; map it to a CLI mode value. */
export function parseMode(raw) {
  // Proxy mode appends its listener: "WarpProxy on port 41000".
  const value = String(raw ?? "").trim().toLowerCase().split(/\s+/)[0]
  if (!value) return ""
  if (value === "proxy" || value === "warpproxy") return "proxy"
  if (value === "warp") return "warp"
  if (value === "doh") return "doh"
  if (value === "dot") return "dot"
  if (value === "warp+doh" || value === "warpdoh") return "warp+doh"
  if (value === "warp+dot" || value === "warpdot") return "warp+dot"
  if (value === "tunnel_only" || value === "tunnelonly") return "tunnel_only"
  return value
}

/** The listener port `settings list` reports for proxy mode, or 0. */
export function parseProxyPort(raw) {
  const match = String(raw ?? "").match(/\bport\s+(\d{1,5})\b/i)
  const port = match ? Number(match[1]) : 0
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : 0
}

/**
 * Find `warp-cli` without assuming the installer put it on PATH. Windows is
 * the target; the PATH scan keeps an explicitly installed client working.
 */
export function findWarpCli({ env = process.env, platform = process.platform, exists = fs.existsSync } = {}) {
  const explicit = String(env.WARP_CLI ?? "").trim()
  if (explicit) return explicit
  const names = platform === "win32" ? ["warp-cli.exe", "warp-cli"] : ["warp-cli"]
  const dirs = String(env.PATH ?? env.Path ?? "")
    .split(path.delimiter)
    .filter(Boolean)
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = path.join(dir, name)
      if (exists(candidate)) return candidate
    }
  }
  if (platform === "win32") {
    const bases = [env.ProgramFiles, env["ProgramFiles(x86)"], "C:\\Program Files", "C:\\Program Files (x86)"]
    for (const base of bases) {
      if (!base) continue
      const candidate = path.join(base, "Cloudflare", "Cloudflare WARP", "warp-cli.exe")
      if (exists(candidate)) return candidate
    }
  }
  return ""
}

function execFileAsync(file, args, { timeout = 15_000 } = {}) {
  return new Promise((resolve, reject) => {
    execFile(
      file,
      args,
      { timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          const detail = String(stderr || stdout || err.message).trim()
          reject(new Error(detail || err.message))
          return
        }
        resolve(String(stdout ?? ""))
      },
    )
  })
}

function execFileSyncText(file, args, { timeout = 10_000 } = {}) {
  return execFileSync(file, args, {
    timeout,
    windowsHide: true,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  })
}

/**
 * @param {object} opts
 * @param {object} opts.config        live config view (warpEnabled, warpProxy, ...)
 * @param {(msg: string) => void} [opts.log]
 * @param {() => number} [opts.now]
 * @param {(file: string, args: string[], opts?: object) => Promise<string>} [opts.run]
 * @param {(file: string, args: string[], opts?: object) => string} [opts.runSync]
 * @param {(url: string, init?: object) => Promise<Response>} [opts.fetchImpl]
 * @param {(url: string, init?: object) => Promise<Response>} [opts.probeFetch]
 * @param {(ms: number) => Promise<void>} [opts.sleep]
 * @param {() => boolean} [opts.runtime]  false under Node, whose fetch ignores `proxy`
 * @param {(file: string) => boolean} [opts.exists]
 */
export function createWarp(opts = {}) {
  const config = opts.config ?? {}
  const log = opts.log ?? (() => {})
  const now = opts.now ?? (() => Date.now())
  const run = opts.run ?? execFileAsync
  const runSync = opts.runSync ?? execFileSyncText
  const fetchImpl = opts.fetchImpl ?? ((url, init) => fetch(url, init))
  const probeFetch = opts.probeFetch ?? ((url, init) => fetch(url, init))
  const sleep = opts.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)))
  const runtime = opts.runtime ?? (() => typeof Bun !== "undefined")
  const exists = opts.exists ?? fs.existsSync

  let started = false
  let starting = null
  let state = "off" // off | booting | hot | degraded | dead
  let error = ""
  let info = {}
  let served = 0
  let lastProbeAt = 0
  let lastFetchAt = 0
  let retryAt = 0
  let probeTimer = null
  // Sticky rotation state: one reconnect at a time, and a generation counter so
  // a stop() that lands mid-rotation cannot be undone by the rotation finishing.
  let rotating = null
  let rotations = 0
  let lastRotateAt = 0
  let lastReason = ""
  let epoch = 0

  // Captured once per lifecycle so a reconnect does not overwrite the state we
  // promised to restore on stop.
  let captured = false
  let priorMode = ""
  let priorPort = 0
  let priorConnected = false
  let connectedByUs = false

  const enabled = () => Boolean(config.warpEnabled)
  const managed = () => config.warpManage !== false
  const probeMs = () => Math.max(10_000, Number(config.warpProbeMs) || DEFAULT_PROBE_MS)

  function proxy() {
    return normalizeProxyUrl(config.warpProxy)
  }

  function cli() {
    return String(config.warpCli ?? "").trim() || findWarpCli({ exists })
  }

  function connected(status) {
    return String(status?.status ?? "").toLowerCase() === "connected"
  }

  async function cliStatus(bin) {
    const out = await run(bin, ["--json", "status"], { timeout: 10_000 })
    try {
      return JSON.parse(out)
    } catch {
      return { status: String(out ?? "").trim() }
    }
  }

  async function cliMode(bin) {
    const out = await run(bin, ["settings", "list"], { timeout: 10_000 })
    const match = String(out ?? "").match(/^\s*(?:\([^)]*\)\s*)?Mode:\s*(.+)$/im)
    const raw = match ? match[1] : ""
    return { mode: parseMode(raw), port: parseProxyPort(raw) }
  }

  async function capturePrior(bin) {
    if (captured) return
    const prior = await cliMode(bin).catch(() => ({ mode: "", port: 0 }))
    const status = await cliStatus(bin).catch(() => ({}))
    // The consumer client's default is Warp; if the display name is something
    // this build does not know, restoring to Warp is the least surprising.
    priorMode = prior.mode || "warp"
    priorPort = prior.port
    priorConnected = connected(status)
    connectedByUs = !priorConnected
    captured = true
  }

  async function connectIfNeeded(bin) {
    const before = await cliStatus(bin).catch(() => ({}))
    if (connected(before)) return
    await run(bin, ["connect"], { timeout: 20_000 })
    const deadline = Date.now() + CONNECT_TIMEOUT_MS
    while (Date.now() < deadline) {
      const status = await cliStatus(bin).catch(() => ({}))
      if (connected(status)) return
      await sleep(500)
    }
    throw new Error("WARP did not report Connected within 30s")
  }

  async function probe() {
    const res = await probeFetch(WARP_TRACE_URL, {
      proxy: proxy(),
      signal: AbortSignal.timeout(15_000),
      headers: { "user-agent": "zen-proxy-warp/1" },
    })
    const text = await res.text()
    if (!res.ok) throw new Error(`WARP trace returned ${res.status}`)
    const trace = parseTrace(text)
    // This is the guarantee: a proxy that is not actually WARP is refused
    // rather than treated as a working egress.
    if (trace.warp !== "on") {
      throw new Error("WARP trace did not report warp=on — traffic is not on WARP")
    }
    return { ...trace, at: now() }
  }

  async function probeOrThrow(attempts) {
    let last = null
    for (let i = 0; i < attempts; i++) {
      try {
        info = await probe()
        lastProbeAt = now()
        return
      } catch (err) {
        last = err
        if (i + 1 < attempts) await sleep(1000)
      }
    }
    throw last ?? new Error("WARP probe failed")
  }

  function scheduleProbe() {
    if (probeTimer) clearInterval(probeTimer)
    probeTimer = setInterval(() => {
      checkHealth().catch(() => {})
    }, probeMs())
    probeTimer.unref?.()
  }

  async function checkHealth() {
    if (!enabled() || state !== "hot") return
    try {
      info = await probe()
      lastProbeAt = now()
      error = ""
    } catch (err) {
      state = "degraded"
      error = `WARP health check failed: ${err.message}`
      retryAt = 0
      if (managed()) start().catch(() => {})
    }
  }

  async function start() {
    if (!enabled()) {
      state = "off"
      return status()
    }
    if (config.torEnabled) {
      // Tor lanes own the identity and the egress. WARP stays off rather than
      // racing two transports against each other.
      state = "off"
      return status()
    }
    if (started && state === "hot") return status()
    if (starting) return starting
    if (now() < retryAt) return status()

    if (!runtime()) {
      const wasDead = state === "dead"
      state = "dead"
      error = "WARP needs Bun — Node's fetch ignores the proxy option"
      retryAt = now() + NODE_RETRY_MS
      if (!wasDead) log(`warp: ${error}; requests fail rather than ride your own address`)
      return status()
    }

    starting = (async () => {
      state = "booting"
      error = ""
      try {
        const url = proxy()
        if (managed()) {
          const bin = cli()
          if (!bin) throw new Error("warp-cli not found; install Cloudflare WARP or set warpCli")
          const port = proxyPort(url)
          if (!port) throw new Error(`managed WARP needs a local proxy URL (got ${url})`)
          await capturePrior(bin)
          const current = await cliMode(bin).catch(() => ({ mode: priorMode }))
          if (current.mode !== "proxy") await run(bin, ["mode", "proxy"], { timeout: 15_000 })
          await run(bin, ["proxy", "port", String(port)], { timeout: 10_000 })
          await connectIfNeeded(bin)
        }
        // Managed mode gets a few tries: `connect` reports Success before the
        // tunnel is always usable. External mode gets one honest answer.
        await probeOrThrow(managed() ? 12 : 1)
        started = true
        state = "hot"
        error = ""
        scheduleProbe()
        log(`warp: tunnel up${info.ip ? ` via ${info.ip}` : ""}`)
      } catch (err) {
        state = "degraded"
        error = err.message
        retryAt = now() + RETRY_MS
        log(`warp: ${err.message}`)
      } finally {
        starting = null
      }
      return status()
    })()
    return starting
  }

  /**
   * Ask the client for a new egress address: disconnect, reconnect, and prove
   * the tunnel again. One WARP registration is one tunnel, so this is the only
   * way to change the exit — which is also why rotation needs managed mode.
   *
   * Sticky mode calls this after a refusal. The caller mints a new identity
   * once this returns, so the pair and the address always move together.
   */
  async function rotate(reason = "") {
    if (!enabled()) throw new Error("WARP is not enabled")
    if (!managed()) throw new Error("WARP rotation needs managed mode (warpManage)")
    if (rotating) return rotating
    const myEpoch = epoch
    rotating = (async () => {
      if (state !== "hot") {
        await start()
        if (state !== "hot") throw new Error(error || "WARP is not ready")
      }
      const bin = cli()
      if (!bin) throw new Error("warp-cli not found; install Cloudflare WARP or set warpCli")
      const before = info.ip
      const tries = Math.max(1, Math.min(6, Number(config.warpRotateTries) || 4))
      let lastError = ""
      for (let i = 0; i < tries; i++) {
        if (myEpoch !== epoch || !enabled()) throw new Error("WARP stopped")
        try {
          await run(bin, ["disconnect"], { timeout: 10_000 })
          await sleep(500)
          if (myEpoch !== epoch || !enabled()) throw new Error("WARP stopped")
          await run(bin, ["connect"], { timeout: 20_000 })
          await connectIfNeeded(bin)
          if (myEpoch !== epoch || !enabled()) throw new Error("WARP stopped")
          await probeOrThrow(managed() ? 12 : 1)
          state = "hot"
          error = ""
        } catch (err) {
          if (myEpoch !== epoch || !enabled() || /WARP stopped/.test(err.message)) throw err
          lastError = err.message
          state = "degraded"
          error = `WARP rotation failed: ${err.message}`
          continue
        }
        if (info.ip && info.ip !== before) {
          rotations += 1
          lastRotateAt = now()
          lastReason = String(reason || "")
          log(`warp: rotated to ${info.ip}${reason ? ` (${reason})` : ""}`)
          return status()
        }
        lastError = "WARP handed back the same egress address"
      }
      error = `WARP could not rotate: ${lastError || "no new egress address"}`
      throw new Error(error)
    })().finally(() => {
      if (myEpoch === epoch) rotating = null
    })
    return rotating
  }

  async function ensure() {
    if (!enabled()) return
    if (state === "hot") return
    if (starting) {
      await starting
      if (state !== "hot") throw new Error(error || "WARP is not ready")
      return
    }
    if (now() < retryAt) throw new Error(error || "WARP is not ready")
    await start()
    if (state !== "hot") throw new Error(error || "WARP is not ready")
  }

  async function warpFetch(url, init = {}) {
    if (!enabled()) return fetchImpl(url, init)
    await ensure()
    const urlProxy = proxy()
    try {
      const res = await fetchImpl(url, { ...init, proxy: urlProxy })
      served += 1
      lastFetchAt = now()
      return res
    } catch (err) {
      state = "degraded"
      error = `WARP request failed: ${err.message}`
      retryAt = 0
      // A dropped tunnel is worth one background reconnect; the caller still
      // sees the failure, and the retry loop can pick the recovered tunnel up.
      if (managed()) start().catch(() => {})
      throw new Error(error)
    }
  }

  function stop() {
    // Invalidate an in-flight rotation: it must not reconnect after we restore.
    epoch += 1
    rotating = null
    if (probeTimer) clearInterval(probeTimer)
    probeTimer = null
    if (managed() && captured) {
      const bin = cli()
      const mode = priorMode || "warp"
      try {
        // Disconnect before changing modes; the client refuses some mode
        // switches while connected.
        if (connectedByUs || mode !== "proxy") {
          runSync(bin, ["disconnect"], { timeout: 10_000 })
        }
        if (mode !== "proxy") runSync(bin, ["mode", mode], { timeout: 10_000 })
        // Proxy mode keeps the listener port as a setting; put theirs back.
        if (mode === "proxy" && priorPort) {
          runSync(bin, ["proxy", "port", String(priorPort)], { timeout: 10_000 })
        }
        if (priorConnected && mode !== "proxy") {
          runSync(bin, ["connect"], { timeout: 15_000 })
        }
      } catch (err) {
        log(`warp: could not restore the client (${err.message})`)
      }
    }
    captured = false
    priorMode = ""
    priorPort = 0
    priorConnected = false
    connectedByUs = false
    started = false
    starting = null
    retryAt = 0
    state = "off"
    error = ""
    info = {}
    rotations = 0
    lastRotateAt = 0
    lastReason = ""
  }

  function status() {
    let url = ""
    try {
      url = proxy()
    } catch {
      url = String(config.warpProxy ?? DEFAULT_WARP_PROXY)
    }
    return {
      enabled: enabled(),
      active: enabled() && !config.torEnabled && state === "hot",
      managed: managed(),
      state: enabled() ? state : "off",
      proxy: url,
      ip: info.ip || "",
      warp: info.warp || "",
      loc: info.loc || "",
      colo: info.colo || "",
      served,
      error: enabled() ? error : "",
      note: config.torEnabled && enabled() ? "Tor lanes take precedence" : "",
      since: info.at || 0,
      lastProbeAt,
      lastFetchAt,
      client: managed() ? cli() : "",
      sticky: config.warpSticky !== false && managed(),
      rotations,
      lastRotateAt,
      lastReason,
    }
  }

  return {
    start,
    stop,
    status,
    probe,
    rotate,
    fetch: warpFetch,
    get state() {
      return state
    },
    get started() {
      return started
    },
    get info() {
      return info
    },
  }
}
