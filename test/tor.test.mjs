import { test, describe, after, beforeEach } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import zlib from "node:zlib"
import {
  BLOCKED,
  EXIT_CAP,
  FREE_LIMIT,
  GATE,
  Ledger,
  RATE_LIMIT,
  classifyFailure,
  createLanes,
  discoverExits,
  ensureTorBinary,
  findOnPath,
  findTorUnder,
  geoipFor,
  nextUtcMidnight,
  parseCountries,
  retryAfterMs,
  torAsset,
  unpackTarGz,
  utcDayStart,
} from "../tor.mjs"

const realFetch = globalThis.fetch
after(() => {
  globalThis.fetch = realFetch
})

// ---------------------------------------------------------------------------
// countries.txt, exactly as lingling reads it
// ---------------------------------------------------------------------------

describe("countries file", () => {
  test("three lines are the primary, fallback and preferred pools", () => {
    const pools = parseCountries("de,nl,se\nsg,ro\nfr\n")
    assert.deepEqual(pools.primary, ["de", "nl", "se"])
    assert.deepEqual(pools.fallback, ["sg", "ro"])
    assert.deepEqual(pools.preferred, ["fr"])
  })

  test("a comment-only line is ignored entirely, not treated as a pool", () => {
    const pools = parseCountries("# big pools first\nde,nl\n# fallback\nsg\n")
    assert.deepEqual(pools.primary, ["de", "nl"])
    assert.deepEqual(pools.fallback, ["sg"])
  })

  test("a blank line skips that pool instead of shifting the next line into it", () => {
    const pools = parseCountries("de\n\nfr\n")
    assert.deepEqual(pools.primary, ["de"])
    assert.deepEqual(pools.fallback, [])
    assert.deepEqual(pools.preferred, ["fr"])
  })

  test("trailing comments are cut, codes are lowercased, junk is dropped", () => {
    const pools = parseCountries("DE, usa ,x1, nl # germany and friends\n")
    assert.deepEqual(pools.primary, ["de", "nl"])
  })

  test("an empty or missing file yields no pools", () => {
    assert.deepEqual(parseCountries("").primary, [])
    assert.deepEqual(parseCountries(undefined).primary, [])
  })
})

// ---------------------------------------------------------------------------
// classifyFailure: which notepad section a refusal belongs in
// ---------------------------------------------------------------------------

describe("failure classification", () => {
  const now = Date.UTC(2026, 9, 29, 12, 0, 0)

  test("the day's wall without a header runs until 00:00 UTC", () => {
    const verdict = classifyFailure(429, '{"error":{"type":"FreeUsageLimitError"}}', null, now)
    assert.equal(verdict.reason, FREE_LIMIT)
    assert.equal(verdict.until, nextUtcMidnight(now))
  })

  test("the day's wall honours the reset it names", () => {
    const verdict = classifyFailure(429, "Free usage limit reached", "3600", now)
    assert.equal(verdict.reason, FREE_LIMIT)
    assert.equal(verdict.until, now + 3_600_000)
  })

  test("no exit is ever written off for more than a day", () => {
    const verdict = classifyFailure(429, "Free usage limit reached", "9999999", now)
    assert.ok(verdict.until - now <= 24 * 3600_000, "capped at a day")
  })

  test("the burst ceiling is minutes, not a day", () => {
    const verdict = classifyFailure(429, '{"error":{"type":"RateLimited"}}', null, now)
    assert.equal(verdict.reason, RATE_LIMIT)
    assert.equal(verdict.until - now, 25 * 60_000)
  })

  test("opencode's own edge is never charged to the exit", () => {
    const verdict = classifyFailure(429, '{"error":{"message":"Endpoint is unavailable"}}', null, now)
    assert.equal(verdict.reason, null)
    assert.equal(verdict.edge, true)
  })

  test("403 FreeTierError is the gate: the exit sits out minutes, not the day", () => {
    const verdict = classifyFailure(403, '{"error":{"type":"FreeTierError"}}', null, now)
    assert.equal(verdict.reason, GATE)
    assert.equal(verdict.until - now, 5 * 60_000)
  })

  test("a 403 that is not the gate is treated as a blocked exit", () => {
    const verdict = classifyFailure(403, "Forbidden", null, now)
    assert.equal(verdict.reason, BLOCKED)
  })

  test("retry-after accepts seconds and HTTP dates", () => {
    assert.equal(retryAfterMs("120", 1000), 121_000)
    assert.equal(retryAfterMs(new Date(1000 + 60_000).toUTCString(), 1000), 60_000)
    assert.equal(retryAfterMs("", 1000), 0)
    assert.equal(retryAfterMs("nonsense", 1000), 0)
  })

  test("nextUtcMidnight is the following midnight in UTC", () => {
    assert.equal(new Date(nextUtcMidnight(Date.UTC(2026, 9, 29, 23, 59, 59))).toISOString(), "2026-10-30T00:00:00.000Z")
    assert.equal(new Date(nextUtcMidnight(Date.UTC(2026, 9, 29, 0, 0, 0))).toISOString(), "2026-10-30T00:00:00.000Z")
  })
})

// ---------------------------------------------------------------------------
// the ledger
// ---------------------------------------------------------------------------

describe("ledger", () => {
  let dir
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "zen-tor-ledger-"))
  })

  test("a noted exit sits out, and a 200 clears its record", () => {
    const now = 1_000_000
    const ledger = new Ledger("", () => now)
    ledger.note("A".repeat(40), RATE_LIMIT, now + 60_000)
    assert.equal(ledger.limited("A".repeat(40)), true)
    assert.equal(ledger.reasonFor("A".repeat(40)), RATE_LIMIT)
    ledger.noteOk("A".repeat(40))
    assert.equal(ledger.limited("A".repeat(40)), false)
  })

  test("a verdict on the books is never shortened by a later one", () => {
    const now = 1_000_000
    const ledger = new Ledger("", () => now)
    const fp = "B".repeat(40)
    ledger.note(fp, FREE_LIMIT, now + 5 * 3600_000)
    ledger.note(fp, RATE_LIMIT, now + 60_000)
    assert.equal(ledger.reasonFor(fp), FREE_LIMIT, "the day's wall still stands")
  })

  test("an expired entry is not limited and does not survive the clock", () => {
    let now = 1_000_000
    const ledger = new Ledger("", () => now)
    const fp = "C".repeat(40)
    ledger.note(fp, RATE_LIMIT, now + 1000)
    now += 2000
    assert.equal(ledger.limited(fp), false)
  })

  test("the ledger survives a restart", () => {
    const now = 1_000_000
    const file = path.join(dir, "tor-ledger.json")
    const fp = "D".repeat(40)
    new Ledger(file, () => now).note(fp, FREE_LIMIT, now + 3600_000)
    const reloaded = new Ledger(file, () => now)
    assert.equal(reloaded.limited(fp), true)
    assert.equal(reloaded.reasonFor(fp), FREE_LIMIT)
  })

  test("usage is counted per exit", () => {
    const ledger = new Ledger("", () => 0)
    const fp = "E".repeat(40)
    ledger.spend(fp)
    ledger.spend(fp)
    assert.equal(ledger.usageFor(fp).requests, 2)
    ledger.forget(fp)
    assert.equal(ledger.usageFor(fp).requests, 0)
  })

  test("usage is per UTC day: yesterday's spending is not today's", () => {
    let now = Date.UTC(2026, 9, 29, 23, 0, 0)
    const ledger = new Ledger("", () => now)
    const fp = "F".repeat(40)
    ledger.spend(fp)
    ledger.spend(fp)
    assert.equal(ledger.usageFor(fp).requests, 2)
    now = utcDayStart(now) + 24 * 3600_000 + 1000
    assert.equal(ledger.usageFor(fp).requests, 0, "a new day starts every exit at zero")
    ledger.spend(fp)
    assert.equal(ledger.usageFor(fp).requests, 1)
  })
})

// ---------------------------------------------------------------------------
// exit discovery
// ---------------------------------------------------------------------------

describe("exit discovery", () => {
  test("only running relays carrying the Exit flag are usable, grouped by country", async () => {
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          relays: [
            { fingerprint: "A".repeat(40), nickname: "one", country: "de", flags: ["Exit", "Fast"] },
            { fingerprint: "B".repeat(40), nickname: "two", country: "de", flags: ["Exit"] },
            { fingerprint: "C".repeat(40), nickname: "three", country: "nl", flags: ["Guard"] },
            { fingerprint: "not-a-fingerprint", nickname: "bad", country: "nl", flags: ["Exit"] },
            { fingerprint: "D".repeat(40), nickname: "four", country: "SE", flags: ["Exit"] },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )
    const { byCountry } = await discoverExits()
    assert.equal(byCountry.get("de").length, 2)
    assert.equal(byCountry.get("nl"), undefined, "a relay without the Exit flag is not an exit")
    assert.equal(byCountry.get("se").length, 1, "country codes are normalised")
  })

  test("a failing directory is an error, never a silent empty pool", async () => {
    globalThis.fetch = async () => new Response("nope", { status: 502 })
    await assert.rejects(() => discoverExits(), /onionoo 502/)
  })
})

// ---------------------------------------------------------------------------
// the race
// ---------------------------------------------------------------------------

/** A lane that looks exactly like the real thing to everything but tor itself. */
function fakeLane(index, fingerprint, extra = {}) {
  return {
    index,
    state: "hot",
    tunnelPort: 20000 + index,
    fingerprint,
    nickname: `relay${index}`,
    country: "de",
    exitIp: `10.0.0.${index}`,
    active: 0,
    requests: 0,
    ridingSince: 1_000_000,
    identity: { session: `ses_lane_${index}`, project: `prj_lane_${index}` },
    label: `lane ${index} {de}`,
    short: () => fingerprint.slice(0, 8),
    busyUntil: 0,
    // The real thing is a getter on the Lane class; the stub has to expose the
    // same seam or no copy is routed to it.
    get proxyUrl() {
      return `http://127.0.0.1:${this.tunnelPort}`
    },
    ...extra,
  }
}

function makeManager({ lanes = [], config = {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zen-tor-run-"))
  const manager = createLanes({
    config: {
      torLanes: lanes.length || 10,
      torRaceWidth: 5,
      torRounds: 2,
      torExitSoftCap: 100,
      torExitHoldS: 600,
      torSweepMoves: 3,
      torDataDir: dir,
      torProof: false,
      ua: "opencode/latest/2.1.4/cli",
      timeoutMs: 5000,
      torStreamGraceS: 120,
      ...config,
    },
    log: () => {},
    mintIdentity: () => ({ session: "ses_minted", project: "prj_minted" }),
  })
  manager.lanes.push(...lanes)
  return manager
}

/** Answer per lane: the stub routes on the proxy URL the copy carries. */
function stubPerLane(handlers) {
  const calls = []
  globalThis.fetch = async (url, init = {}) => {
    const port = Number(String(init.proxy || "").split(":").pop())
    const lane = port - 20000
    calls.push({ lane, headers: { ...(init.headers || {}) }, url, signal: init.signal })
    const handler = handlers[lane]
    if (!handler) throw new Error(`no stub for lane ${lane}`)
    return handler(url, init)
  }
  return calls
}

const ok200 = () => new Response("ok", { status: 200 })

describe("the race", () => {
  test("the first 200 takes the call and the losers are charged their refusals", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40)), fakeLane(2, "2".repeat(40))]
    const manager = makeManager({ lanes })
    // Lane 1 is slow; 0 and 2 are refused for the day.
    const calls = stubPerLane({
      0: () => new Response("Free usage limit reached", { status: 429 }),
      1: async () => {
        await new Promise((r) => setTimeout(r, 30))
        return new Response("ok", { status: 200 })
      },
      2: () => new Response('{"error":{"type":"FreeUsageLimitError"}}', { status: 429 }),
    })
    const res = await manager.fetch("https://opencode.ai/x", { method: "POST", headers: {} }, {})
    assert.equal(res.status, 200)
    assert.equal(calls.length, 3, "all three lanes were in the wave")
    // The losers' verdicts land in the background, after their bodies were read.
    await new Promise((r) => setTimeout(r, 250))
    assert.equal(manager.ledger.reasonFor("0".repeat(40)), FREE_LIMIT)
    assert.equal(manager.ledger.reasonFor("2".repeat(40)), FREE_LIMIT)
    assert.equal(manager.ledger.reasonFor("1".repeat(40)), "", "the winning exit keeps a clean record")
  })

  test("a refusal is never charged to the winning exit", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40))]
    const manager = makeManager({ lanes })
    stubPerLane({ 0: () => new Response("nope", { status: 429 }), 1: () => new Response("ok", { status: 200 }) })
    await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    assert.equal(manager.ledger.reasonFor("1".repeat(40)), "")
  })

  test("the far end's own bad moment is not written against the exit", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40)), fakeLane(2, "2".repeat(40))]
    const manager = makeManager({ lanes })
    stubPerLane({
      0: () => new Response("bad gateway", { status: 502 }),
      1: async () => {
        await new Promise((r) => setTimeout(r, 20))
        return new Response("ok", { status: 200 })
      },
      2: () => new Response("also bad", { status: 503 }),
    })
    const res = await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    assert.equal(res.status, 200)
    await new Promise((r) => setTimeout(r, 250))
    assert.equal(manager.ledger.reasonFor("0".repeat(40)), "", "502 is the edge, not the exit")
    assert.equal(manager.ledger.reasonFor("2".repeat(40)), "")
  })

  test("403 FreeTierError sits the exit out for minutes, and a sibling still serves", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40))]
    const manager = makeManager({ lanes })
    stubPerLane({
      0: () => new Response('{"error":{"type":"FreeTierError"}}', { status: 403 }),
      1: async () => {
        await new Promise((r) => setTimeout(r, 20))
        return new Response("ok", { status: 200 })
      },
    })
    const res = await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    assert.equal(res.status, 200, "a gated sibling does not take the call")
    await new Promise((r) => setTimeout(r, 250))
    assert.equal(manager.ledger.reasonFor("0".repeat(40)), GATE)
  })

  test("each copy carries its own lane's identity, paired with that lane's exit", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40))]
    const manager = makeManager({ lanes })
    const calls = stubPerLane({
      0: () => new Response("nope", { status: 500 }),
      1: async () => {
        await new Promise((r) => setTimeout(r, 10))
        return ok200()
      },
    })
    await manager.fetch("https://opencode.ai/x", { headers: { "x-opencode-session": "ses_caller" } }, { identity: true })
    const byLane = Object.fromEntries(calls.map((c) => [c.lane, c.headers]))
    assert.equal(byLane[0]["x-opencode-session"], "ses_lane_0")
    assert.equal(byLane[1]["x-opencode-session"], "ses_lane_1")
    assert.equal(byLane[1]["x-opencode-project"], "prj_lane_1")
    assert.equal(byLane[1]["x-session-affinity"], "ses_lane_1", "the affinity pair travels too")
  })

  test("a caller's own session is never fanned out: one lane, identity untouched", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40)), fakeLane(2, "2".repeat(40))]
    const manager = makeManager({ lanes })
    const calls = stubPerLane({ 0: ok200, 1: ok200, 2: ok200 })
    const res = await manager.fetch(
      "https://opencode.ai/x",
      { headers: { "x-opencode-session": "ses_caller_owned", "x-opencode-project": "prj_caller" } },
      { identity: false, stickyKey: "ses_caller_owned" },
    )
    assert.equal(res.status, 200)
    assert.equal(calls.length, 1, "exactly one exit saw this session")
    assert.equal(calls[0].headers["x-opencode-session"], "ses_caller_owned")
    assert.equal(calls[0].headers["x-opencode-project"], "prj_caller")
  })

  test("a caller-owned session still charges the exit it was refused by", async () => {
    const lanes = [fakeLane(0, "0".repeat(40))]
    const manager = makeManager({ lanes })
    stubPerLane({ 0: () => new Response("Free usage limit reached", { status: 429 }) })
    const res = await manager.fetch(
      "https://opencode.ai/x",
      { headers: { "x-opencode-session": "ses_caller_owned" } },
      { identity: false, stickyKey: "ses_caller_owned" },
    )
    assert.equal(res.status, 429)
    assert.equal(manager.ledger.reasonFor("0".repeat(40)), FREE_LIMIT)
  })

  test("when every exit is refused the far end's own words reach the client", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40))]
    const manager = makeManager({ lanes })
    stubPerLane({
      0: () => new Response('{"error":{"type":"FreeUsageLimitError"}}', { status: 429 }),
      1: () => new Response('{"error":{"type":"FreeUsageLimitError"}}', { status: 429 }),
    })
    const res = await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    assert.equal(res.status, 429)
    assert.equal(manager.ledger.reasonFor("0".repeat(40)), FREE_LIMIT)
    assert.equal(manager.ledger.reasonFor("1".repeat(40)), FREE_LIMIT)
  })

  test("a lane whose exit is spent is not raced again", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40))]
    const manager = makeManager({ lanes })
    manager.ledger.note("0".repeat(40), FREE_LIMIT, Date.now() + 3600_000)
    const calls = stubPerLane({ 0: ok200, 1: ok200 })
    await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    assert.deepEqual(
      calls.map((c) => c.lane),
      [1],
      "only the healthy lane was used",
    )
  })

  test("context is required in the race: both signals are the caller's and the lane's", async () => {
    const lanes = [fakeLane(0, "0".repeat(40))]
    const manager = makeManager({ lanes })
    const calls = stubPerLane({ 0: ok200 })
    const wall = AbortSignal.timeout(5000)
    await manager.fetch("https://opencode.ai/x", { headers: {}, signal: wall }, {})
    assert.ok(calls[0].signal instanceof AbortSignal, "the copy carries a real signal")
  })

  test("a delivered answer counts against the exit's own soft cap", async () => {
    const lanes = [fakeLane(0, "0".repeat(40))]
    const manager = makeManager({ lanes })
    stubPerLane({ 0: ok200 })
    await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    assert.equal(lanes[0].requests, 1, "the sweep reads lane.requests, so it must move")
  })

  test("a caller's session keeps the lane it first met as the pool changes", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40))]
    const manager = makeManager({ lanes })
    const calls = stubPerLane({ 0: ok200, 1: ok200 })
    const opts = { identity: false, stickyKey: "ses_caller_sticky" }
    const headers = { "x-opencode-session": "ses_caller_sticky" }
    await manager.fetch("https://opencode.ai/x", { headers }, opts)
    const first = calls[0].lane
    // A hash over the live pool would remap this session to the other exit the
    // moment the array order changes. The pin must survive it.
    manager.lanes.reverse()
    await manager.fetch("https://opencode.ai/x", { headers }, opts)
    assert.equal(calls[1].lane, first, "one session, one exit")
  })
})

describe("sticky mode", () => {
  const softCap = Math.floor(EXIT_CAP / 2)

  test("one lane carries every call until it is refused", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40)), fakeLane(2, "2".repeat(40))]
    const manager = makeManager({ lanes, config: { torSticky: true } })
    const calls = stubPerLane({ 0: ok200, 1: ok200, 2: ok200 })
    await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    assert.deepEqual(
      calls.map((c) => c.lane),
      [0, 0],
      "the same exit serves both calls instead of racing a wave",
    )
  })

  test("a refused exit hands over to the next lane, which becomes the pin", async () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40)), fakeLane(2, "2".repeat(40))]
    const manager = makeManager({ lanes, config: { torSticky: true } })
    const calls = stubPerLane({
      0: () => new Response("Free usage limit reached", { status: 429 }),
      1: ok200,
      2: ok200,
    })
    const res = await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    assert.equal(res.status, 200)
    assert.deepEqual(
      calls.map((c) => c.lane),
      [0, 1],
      "lane 0 was refused, lane 1 served",
    )
    assert.equal(manager.ledger.reasonFor("0".repeat(40)), FREE_LIMIT)
    // The next call keeps riding lane 1, not the refused lane or a fresh race.
    calls.length = 0
    await manager.fetch("https://opencode.ai/x", { headers: {} }, {})
    assert.deepEqual(
      calls.map((c) => c.lane),
      [1],
    )
  })

  test("anonymous calls carry the lane identity; a caller-owned one is untouched", async () => {
    const lanes = [fakeLane(0, "0".repeat(40))]
    const manager = makeManager({ lanes, config: { torSticky: true } })
    const calls = stubPerLane({ 0: ok200 })
    await manager.fetch("https://opencode.ai/x", { headers: {} }, { identity: true })
    assert.equal(calls[0].headers["x-opencode-session"], "ses_lane_0")
    await manager.fetch(
      "https://opencode.ai/x",
      { headers: { "x-opencode-session": "ses_caller" } },
      { identity: false, stickyKey: "ses_caller" },
    )
    assert.equal(calls[1].headers["x-opencode-session"], "ses_caller")
  })

  test("the sweep leaves a working lane alone in sticky mode", async () => {
    const lane = fakeLane(0, "0".repeat(40), { requests: softCap })
    const manager = makeManager({ lanes: [lane], config: { torSticky: true } })
    let moved = 0
    await manager.sweep({
      moveLane: async () => {
        moved += 1
        return true
      },
    })
    assert.equal(moved, 0, "a working exit is the whole point of the mode")
  })

  test("the sweep still moves a refused exit in sticky mode", async () => {
    const lane = fakeLane(0, "0".repeat(40))
    const manager = makeManager({ lanes: [lane], config: { torSticky: true } })
    manager.ledger.note("0".repeat(40), FREE_LIMIT, Date.now() + 60_000)
    let moved = 0
    await manager.sweep({
      moveLane: async () => {
        moved += 1
        return true
      },
    })
    assert.equal(moved, 1)
  })

  test("status reports the mode and the single-lane width", () => {
    const manager = makeManager({ lanes: [fakeLane(0, "0".repeat(40))], config: { torSticky: true } })
    const status = manager.status()
    assert.equal(status.sticky, true)
    assert.equal(status.width, 1)
  })
})

describe("lane selection", () => {
  test("the wave is the least-loaded lanes first", () => {
    const lanes = [
      fakeLane(0, "0".repeat(40), { active: 2 }),
      fakeLane(1, "1".repeat(40), { active: 0 }),
      fakeLane(2, "2".repeat(40), { active: 1 }),
    ]
    const manager = makeManager({ lanes })
    const wave = manager.pickWave(2)
    assert.deepEqual(
      wave.map((l) => l.index),
      [1, 2],
    )
  })

  test("a lane whose exit sits out is not picked", () => {
    const lanes = [fakeLane(0, "0".repeat(40)), fakeLane(1, "1".repeat(40))]
    const manager = makeManager({ lanes })
    manager.ledger.note("1".repeat(40), GATE, Date.now() + 60_000)
    assert.deepEqual(
      manager.pickWave(5).map((l) => l.index),
      [0],
    )
  })

  test("a cold lane is not part of any wave", () => {
    const lanes = [fakeLane(0, "0".repeat(40), { state: "cold" }), fakeLane(1, "1".repeat(40))]
    const manager = makeManager({ lanes })
    assert.deepEqual(
      manager.pickWave(5).map((l) => l.index),
      [1],
    )
  })
})

describe("sweeping", () => {
  const softCap = Math.floor(EXIT_CAP / 2)

  test("a lane that has spent half an exit's day is moved off it", async () => {
    const lane = fakeLane(0, "0".repeat(40), { requests: softCap })
    const manager = makeManager({ lanes: [lane] })
    let moved = 0
    await manager.sweep({
      moveLane: async () => {
        moved += 1
        return true
      },
    })
    assert.equal(moved, 1)
  })

  test("a lane that just delivered a reply is left alone until its body finishes", async () => {
    const lane = fakeLane(0, "0".repeat(40), { requests: softCap, busyUntil: Date.now() + 60_000 })
    const manager = makeManager({ lanes: [lane] })
    let moved = 0
    await manager.sweep({
      moveLane: async () => {
        moved += 1
        return true
      },
    })
    assert.equal(moved, 0)
  })

  test("a lane riding one exit past the hold window is moved", async () => {
    const lane = fakeLane(0, "0".repeat(40), { ridingSince: Date.now() - 3600_000 })
    const manager = makeManager({ lanes: [lane] })
    let moved = 0
    await manager.sweep({
      moveLane: async () => {
        moved += 1
        return true
      },
    })
    assert.equal(moved, 1)
  })

  test("no more than torSweepMoves lanes move per pass", async () => {
    const lanes = [0, 1, 2, 3, 4].map((i) => fakeLane(i, String(i).repeat(40), { requests: softCap }))
    const manager = makeManager({ lanes, config: { torSweepMoves: 2 } })
    let moved = 0
    await manager.sweep({
      moveLane: async () => {
        moved += 1
        return true
      },
    })
    assert.equal(moved, 2)
  })
})

describe("status", () => {
  test("it reports lanes, ledger and the last race without touching tor", () => {
    const lanes = [fakeLane(0, "AB".repeat(20))]
    const manager = makeManager({ lanes, config: { torEnabled: true } })
    manager.ledger.note("0".repeat(40), RATE_LIMIT, Date.now() + 60_000)
    const status = manager.status()
    assert.equal(status.enabled, true)
    assert.equal(status.hot, 1)
    assert.equal(status.lanes.length, 1)
    assert.equal(status.lanes[0].country, "de")
    assert.equal(status.lanes[0].exitIp, "10.0.0.0")
    assert.deepEqual(Object.keys(status.ledger), ["0".repeat(40)], "the ledger travels with the status")
    assert.equal(status.lanes[0].limited, "", "this lane rides a different exit than the limited one")
  })
})

// ---------------------------------------------------------------------------
// getting a tor: the Expert Bundle, and the order we look in
// ---------------------------------------------------------------------------

/** A tar header, hand-built so this test needs no tar binary. */
function tarEntry(name, data, type = "0") {
  const header = Buffer.alloc(512)
  header.write(name, 0, 100, "utf8")
  header.write("0000644\0", 100, 8, "ascii")
  header.write("0000000\0", 108, 8, "ascii")
  header.write("0000000\0", 116, 8, "ascii")
  header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii")
  header.write("00000000000\0", 136, 12, "ascii")
  header.write("        ", 148, 8, "ascii")
  header.write(type, 156, 1, "ascii")
  let sum = 0
  for (const byte of header) sum += byte
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii")
  const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512)
  Buffer.from(data).copy(padded)
  return [header, padded]
}

function tarGz(...entries) {
  const parts = []
  for (const [name, data, type] of entries) parts.push(...tarEntry(name, data, type))
  parts.push(Buffer.alloc(1024))
  return zlib.gzipSync(Buffer.concat(parts))
}

describe("the Tor bundle", () => {
  test("a tar.gz unpacks into the files it holds", () => {
    const entries = unpackTarGz(tarGz(["tor/tor.exe", "MZ-binary-bytes"], ["tor/torrc-defaults", "SocksPort 9050"]))
    assert.deepEqual(
      entries.map((e) => e.name),
      ["tor/tor.exe", "tor/torrc-defaults"],
    )
    assert.equal(entries[0].data.toString(), "MZ-binary-bytes")
  })

  test("a GNU long name renames the entry that follows it", () => {
    // GNU tar writes the long name as an `L` entry's payload; the next header
    // holds a truncated name and inherits the real one.
    const entries = unpackTarGz(
      tarGz(["././@LongLink", "deeply/nested/path/tor.exe", "L"], ["x", "the real file"]),
    )
    assert.deepEqual(
      entries.map((e) => e.name),
      ["deeply/nested/path/tor.exe"],
    )
    assert.equal(entries[0].data.toString(), "the real file")
  })

  test("an archive can never write outside the tools directory", () => {
    const entries = unpackTarGz(tarGz(["../escape.txt", "no"], ["/abs/escape.txt", "no"], ["ok/tor.exe", "yes"]))
    assert.deepEqual(
      entries.map((e) => e.name),
      ["ok/tor.exe"],
    )
  })

  test("the asset name follows the platform", () => {
    assert.equal(torAsset("win32", "x64"), "tor-expert-bundle-windows-x86_64")
    assert.equal(torAsset("darwin", "arm64"), "tor-expert-bundle-macos-aarch64")
    assert.equal(torAsset("linux", "x64"), "tor-expert-bundle-linux-x86_64")
  })
})

describe("tor binary resolution", () => {
  let dir
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "zen-tor-bin-"))
  })

  test("PATH is searched, so an installed tor is used as-is", () => {
    const exe = process.platform === "win32" ? "tor.exe" : "tor"
    const bin = path.join(dir, exe)
    fs.writeFileSync(bin, "#!/bin/sh\n")
    assert.equal(findOnPath(exe, { PATH: dir }), bin)
  })

  test("the binary is found wherever the bundle nests it", () => {
    const exe = process.platform === "win32" ? "tor.exe" : "tor"
    const bin = path.join(dir, "tor-expert-bundle-15.0.26", "tor", exe)
    fs.mkdirSync(path.dirname(bin), { recursive: true })
    fs.writeFileSync(bin, "x")
    assert.equal(findTorUnder(dir), bin)
  })

  test("geoip databases shipped beside the bundle are picked up", () => {
    const exe = process.platform === "win32" ? "tor.exe" : "tor"
    const bin = path.join(dir, "tools", "tor", exe)
    fs.mkdirSync(path.dirname(bin), { recursive: true })
    fs.writeFileSync(bin, "x")
    fs.mkdirSync(path.join(dir, "tools", "data"), { recursive: true })
    fs.writeFileSync(path.join(dir, "tools", "data", "geoip"), "geo")
    fs.writeFileSync(path.join(dir, "tools", "data", "geoip6"), "geo6")
    const geo = geoipFor(bin)
    assert.equal(geo.geoip, path.join(dir, "tools", "data", "geoip"))
    assert.equal(geo.geoip6, path.join(dir, "tools", "data", "geoip6"))
  })

  test("an explicit override wins, and a missing one is an error not a fallback", async () => {
    const bin = path.join(dir, "my-tor")
    fs.writeFileSync(bin, "x")
    assert.equal(await ensureTorBinary({ dataDir: dir, override: bin }), bin)
    await assert.rejects(() => ensureTorBinary({ dataDir: dir, override: path.join(dir, "nope") }), /torBinary not found/)
  })

  test("a bundle from a previous run is reused before anything is downloaded", async () => {
    const exe = path.join(dir, "tools", "tor", process.platform === "win32" ? "tor.exe" : "tor")
    fs.mkdirSync(path.dirname(exe), { recursive: true })
    fs.writeFileSync(exe, "x")
    assert.equal(
      await ensureTorBinary({ dataDir: dir, download: false, versionOf: async () => ({ major: 0, minor: 4, patch: 9 }) }),
      exe,
    )
  })

  test("a stale tor on PATH is refused, never returned", async () => {
    const exe = process.platform === "win32" ? "tor.exe" : "tor"
    const staleDir = path.join(dir, "stale")
    fs.mkdirSync(staleDir, { recursive: true })
    fs.writeFileSync(path.join(staleDir, exe), "x")
    const originalPath = process.env.PATH
    process.env.PATH = staleDir
    try {
      await assert.rejects(
        () => ensureTorBinary({ dataDir: dir, download: false, versionOf: async () => ({ major: 0, minor: 4, patch: 7 }) }),
        /no usable tor found/,
      )
    } finally {
      process.env.PATH = originalPath
    }
  })

  test("a stale bundled tor is skipped too, so a fresher PATH tor wins", async () => {
    const exe = process.platform === "win32" ? "tor.exe" : "tor"
    const bundled = path.join(dir, "tools", "tor", exe)
    const onPath = path.join(dir, "good", exe)
    for (const p of [bundled, onPath]) {
      fs.mkdirSync(path.dirname(p), { recursive: true })
      fs.writeFileSync(p, "x")
    }
    const versionOf = async (bin) =>
      bin === onPath ? { major: 0, minor: 4, patch: 9 } : { major: 0, minor: 4, patch: 7 }
    const originalPath = process.env.PATH
    process.env.PATH = path.dirname(onPath)
    try {
      assert.equal(await ensureTorBinary({ dataDir: dir, download: false, versionOf }), onPath)
    } finally {
      process.env.PATH = originalPath
    }
  })

  test("with no tor anywhere and downloads off, it says so instead of guessing", async () => {
    const originalPath = process.env.PATH
    process.env.PATH = dir
    try {
      await assert.rejects(
        () => ensureTorBinary({ dataDir: dir, download: false }),
        /no usable tor found/,
      )
    } finally {
      process.env.PATH = originalPath
    }
  })
})
