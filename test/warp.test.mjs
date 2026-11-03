import { describe, test } from "node:test"
import assert from "node:assert/strict"
import path from "node:path"
import {
  createWarp,
  findWarpCli,
  normalizeProxyUrl,
  parseMode,
  parseProxyPort,
  parseTrace,
  proxyPort,
} from "../warp.mjs"

const TRACE_ON = "ip=203.0.113.9\nwarp=on\nloc=NL\ncolo=AMS\n"
const TRACE_OFF = "ip=203.0.113.9\nwarp=off\nloc=NL\ncolo=AMS\n"

function fakeClient({ connected = false, mode = "warp", port = 0 } = {}) {
  const calls = []
  const syncCalls = []
  let isConnected = connected
  let listenerPort = port
  const run = async (_bin, args) => {
    calls.push(args.join(" "))
    if (args[0] === "--json") {
      return JSON.stringify({ status: isConnected ? "Connected" : "Disconnected" })
    }
    if (args[0] === "settings") {
      const label = mode === "proxy" ? `WarpProxy${listenerPort ? ` on port ${listenerPort}` : ""}` : "Warp"
      return `(default) Mode: ${label}\n`
    }
    if (args[0] === "mode") {
      mode = args[1]
      return "Success"
    }
    if (args[0] === "proxy") {
      if (args[1] === "port") listenerPort = Number(args[2])
      return "Success"
    }
    if (args[0] === "connect") {
      isConnected = true
      return "Success"
    }
    if (args[0] === "disconnect") {
      isConnected = false
      return "Success"
    }
    return ""
  }
  const runSync = (_bin, args) => {
    syncCalls.push(args.join(" "))
    if (args[0] === "disconnect") isConnected = false
    if (args[0] === "connect") isConnected = true
    if (args[0] === "mode") mode = args[1]
    if (args[0] === "proxy" && args[1] === "port") listenerPort = Number(args[2])
    return ""
  }
  return {
    run,
    runSync,
    calls,
    syncCalls,
    get connected() {
      return isConnected
    },
    get mode() {
      return mode
    },
    get port() {
      return listenerPort
    },
  }
}

describe("warp helpers", () => {
  test("trace parsing reads only the fields the proxy uses", () => {
    assert.deepEqual(parseTrace(TRACE_ON + "gateway=off\n"), {
      ip: "203.0.113.9",
      warp: "on",
      loc: "NL",
      colo: "AMS",
    })
    assert.deepEqual(parseTrace(""), {})
  })

  test("proxy URLs are normalized and local ports are recognized", () => {
    assert.equal(normalizeProxyUrl(""), "http://127.0.0.1:40000")
    assert.equal(normalizeProxyUrl("http://127.0.0.1:41000/"), "http://127.0.0.1:41000")
    assert.throws(() => normalizeProxyUrl("socks5://127.0.0.1:40000"), /http/)
    assert.equal(proxyPort("http://127.0.0.1:41000"), 41000)
    assert.equal(proxyPort("http://localhost:40000"), 40000)
    assert.equal(proxyPort("http://[::1]:40000"), 40000)
    assert.equal(proxyPort("http://192.0.2.10:40000"), 0, "a remote endpoint cannot be managed locally")
  })

  test("client display names map back to CLI mode values", () => {
    assert.equal(parseMode("Warp"), "warp")
    assert.equal(parseMode("WarpProxy"), "proxy")
    // Proxy mode reports its listener on the same line.
    assert.equal(parseMode("WarpProxy on port 41000"), "proxy")
    assert.equal(parseMode("warp+doh"), "warp+doh")
    assert.equal(parseMode(""), "")
    assert.equal(parseProxyPort("WarpProxy on port 41000"), 41000)
    assert.equal(parseProxyPort("Warp"), 0)
  })

  test("warp-cli is found from an explicit path or the Windows install", () => {
    assert.equal(
      findWarpCli({ env: { WARP_CLI: "C:\\custom\\warp-cli.exe" }, platform: "win32", exists: () => false }),
      "C:\\custom\\warp-cli.exe",
    )
    const installed = path.join("C:\\PF", "Cloudflare", "Cloudflare WARP", "warp-cli.exe")
    assert.equal(
      findWarpCli({ env: { ProgramFiles: "C:\\PF" }, platform: "win32", exists: (p) => p === installed }),
      installed,
    )
  })
})

describe("warp transport", () => {
  test("an external proxy is used only after it proves warp=on", async () => {
    const seen = []
    const warp = createWarp({
      config: { warpEnabled: true, warpManage: false, warpProxy: "http://127.0.0.1:41000" },
      runtime: () => true,
      probeFetch: async () => ({ ok: true, text: async () => TRACE_ON }),
      fetchImpl: async (_url, init) => {
        seen.push(init.proxy)
        return { status: 200, ok: true }
      },
    })
    const status = await warp.start()
    assert.equal(status.state, "hot")
    assert.equal(status.ip, "203.0.113.9")
    assert.equal(status.colo, "AMS")
    const res = await warp.fetch("https://upstream.test/v1/chat/completions", { method: "POST" })
    assert.equal(res.status, 200)
    assert.deepEqual(seen, ["http://127.0.0.1:41000"], "the request carries the WARP proxy")
    warp.stop()
  })

  test("a proxy that is not on WARP is refused, never bypassed", async () => {
    let fetched = 0
    const warp = createWarp({
      config: { warpEnabled: true, warpManage: false, warpProxy: "http://127.0.0.1:41000" },
      runtime: () => true,
      probeFetch: async () => ({ ok: true, text: async () => TRACE_OFF }),
      fetchImpl: async () => {
        fetched += 1
        return { status: 200, ok: true }
      },
    })
    const status = await warp.start()
    assert.equal(status.state, "degraded")
    assert.match(status.error, /warp=on/)
    await assert.rejects(
      () => warp.fetch("https://upstream.test/v1/chat/completions"),
      /warp=on|not on WARP/,
    )
    assert.equal(fetched, 0, "no request leaves without a proven WARP tunnel")
    warp.stop()
  })

  test("managed mode switches to proxy, connects, and restores the previous state", async () => {
    const client = fakeClient({ connected: false, mode: "warp" })
    const warp = createWarp({
      config: {
        warpEnabled: true,
        warpManage: true,
        warpProxy: "http://127.0.0.1:41000",
        warpCli: "warp-cli",
      },
      runtime: () => true,
      run: client.run,
      runSync: client.runSync,
      sleep: async () => {},
      probeFetch: async () => ({ ok: true, text: async () => TRACE_ON }),
      fetchImpl: async () => ({ status: 200, ok: true }),
    })
    const status = await warp.start()
    assert.equal(status.state, "hot")
    assert.ok(client.calls.includes("mode proxy"), "the client is switched to proxy mode")
    assert.ok(client.calls.includes("proxy port 41000"), "the listener uses the configured port")
    assert.ok(client.calls.includes("connect"), "the client is connected")
    assert.equal(client.connected, true)

    warp.stop()
    assert.deepEqual(client.syncCalls, ["disconnect", "mode warp"])
    assert.equal(client.connected, false)
    assert.equal(client.mode, "warp")
  })

  test("managed mode reconnects a client that was already connected", async () => {
    const client = fakeClient({ connected: true, mode: "warp" })
    const warp = createWarp({
      config: {
        warpEnabled: true,
        warpManage: true,
        warpProxy: "http://127.0.0.1:41000",
        warpCli: "warp-cli",
      },
      runtime: () => true,
      run: client.run,
      runSync: client.runSync,
      sleep: async () => {},
      probeFetch: async () => ({ ok: true, text: async () => TRACE_ON }),
      fetchImpl: async () => ({ status: 200, ok: true }),
    })
    await warp.start()
    warp.stop()
    assert.deepEqual(client.syncCalls, ["disconnect", "mode warp", "connect"], "the old connection comes back")
    assert.equal(client.connected, true)
  })

  test("a client already in proxy mode keeps its own listener port", async () => {
    const client = fakeClient({ connected: false, mode: "proxy", port: 40000 })
    const warp = createWarp({
      config: {
        warpEnabled: true,
        warpManage: true,
        warpProxy: "http://127.0.0.1:41000",
        warpCli: "warp-cli",
      },
      runtime: () => true,
      run: client.run,
      runSync: client.runSync,
      sleep: async () => {},
      probeFetch: async () => ({ ok: true, text: async () => TRACE_ON }),
      fetchImpl: async () => ({ status: 200, ok: true }),
    })
    await warp.start()
    assert.equal(client.port, 41000, "the tunnel uses the configured port")
    warp.stop()
    assert.deepEqual(client.syncCalls, ["disconnect", "proxy port 40000"], "the prior port comes back")
    assert.equal(client.mode, "proxy")
    assert.equal(client.port, 40000)
  })

  test("sticky rotation reconnects and proves a different address", async () => {
    let ip = "203.0.113.9"
    const client = fakeClient({ connected: true, mode: "proxy", port: 41000 })
    const warp = createWarp({
      config: {
        warpEnabled: true,
        warpManage: true,
        warpSticky: true,
        warpProxy: "http://127.0.0.1:41000",
        warpCli: "warp-cli",
        warpRotateTries: 3,
      },
      runtime: () => true,
      run: async (bin, args) => {
        if (args[0] === "connect") ip = "203.0.113.10"
        return client.run(bin, args)
      },
      runSync: client.runSync,
      sleep: async () => {},
      probeFetch: async () => ({
        ok: true,
        text: async () => `ip=${ip}\nwarp=on\nloc=NL\ncolo=AMS\n`,
      }),
      fetchImpl: async () => ({ status: 200, ok: true }),
    })
    await warp.start()
    assert.equal(warp.status().ip, "203.0.113.9")
    const status = await warp.rotate("test")
    assert.equal(status.ip, "203.0.113.10")
    assert.equal(status.rotations, 1)
    assert.ok(client.calls.includes("disconnect"))
    assert.ok(client.calls.includes("connect"))
    warp.stop()
  })

  test("rotation gives up when the client keeps the same address", async () => {
    const client = fakeClient({ connected: true, mode: "proxy", port: 41000 })
    const warp = createWarp({
      config: {
        warpEnabled: true,
        warpManage: true,
        warpSticky: true,
        warpProxy: "http://127.0.0.1:41000",
        warpCli: "warp-cli",
        warpRotateTries: 2,
      },
      runtime: () => true,
      run: client.run,
      runSync: client.runSync,
      sleep: async () => {},
      probeFetch: async () => ({ ok: true, text: async () => TRACE_ON }),
      fetchImpl: async () => ({ status: 200, ok: true }),
    })
    await warp.start()
    await assert.rejects(() => warp.rotate("test"), /same egress address/)
    assert.equal(warp.status().rotations, 0)
    warp.stop()
  })

  test("rotation refuses external mode, which owns no client", async () => {
    const warp = createWarp({
      config: { warpEnabled: true, warpManage: false, warpProxy: "http://127.0.0.1:41000" },
      runtime: () => true,
      probeFetch: async () => ({ ok: true, text: async () => TRACE_ON }),
      fetchImpl: async () => ({ status: 200, ok: true }),
    })
    await warp.start()
    await assert.rejects(() => warp.rotate("test"), /managed mode/)
    warp.stop()
  })

  test("a failed request degrades the tunnel and the next call retries through it", async () => {
    const proxies = []
    let attempts = 0
    const warp = createWarp({
      config: { warpEnabled: true, warpManage: false, warpProxy: "http://127.0.0.1:41000" },
      runtime: () => true,
      probeFetch: async () => ({ ok: true, text: async () => TRACE_ON }),
      fetchImpl: async (_url, init) => {
        proxies.push(init.proxy)
        attempts += 1
        if (attempts === 1) throw new Error("socket closed")
        return { status: 200, ok: true }
      },
    })
    await warp.start()
    await assert.rejects(() => warp.fetch("https://upstream.test/v1/chat/completions"), /socket closed/)
    assert.equal(warp.state, "degraded")
    const res = await warp.fetch("https://upstream.test/v1/chat/completions")
    assert.equal(res.status, 200)
    assert.deepEqual(proxies, ["http://127.0.0.1:41000", "http://127.0.0.1:41000"])
    warp.stop()
  })

  test("Node is refused because its fetch ignores the proxy option", async () => {
    let fetched = 0
    const warp = createWarp({
      config: { warpEnabled: true, warpManage: false, warpProxy: "http://127.0.0.1:41000" },
      runtime: () => false,
      fetchImpl: async () => {
        fetched += 1
        return { status: 200, ok: true }
      },
    })
    const status = await warp.start()
    assert.equal(status.state, "dead")
    assert.match(status.error, /needs Bun/)
    await assert.rejects(() => warp.fetch("https://upstream.test"), /needs Bun/)
    assert.equal(fetched, 0)
  })

  test("Tor wins when both transports are enabled", async () => {
    const warp = createWarp({
      config: {
        warpEnabled: true,
        torEnabled: true,
        warpManage: false,
        warpProxy: "http://127.0.0.1:41000",
      },
      runtime: () => true,
      probeFetch: async () => ({ ok: true, text: async () => TRACE_ON }),
    })
    const status = await warp.start()
    assert.equal(status.state, "off")
    assert.match(status.note, /Tor/)
  })
})
