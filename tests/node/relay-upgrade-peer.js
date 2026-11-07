'use strict'

// A JS blind relay plus one firewalled JS peer on a local testnet, for the
// relay→direct upgrade tests. argv: server [--no-punch] | client | swarm-server | swarm-client
//
// server: an echo server; a Rust client connects with `relayThrough` set to
//   the relay, so the relay lands first and the holepunch moves the stream.
//   `--no-punch` makes the server refuse to punch, so the stream stays relayed.
// client: reads a server key from stdin, connects with `relayThrough`, sends
//   until the stream has left the relay (or `maxChunks`), then checks the echo.
// swarm-server: a Hyperswarm server echoing data with forced relayThrough.
// swarm-client: a Hyperswarm client connecting via forced relayThrough to a server key from stdin.
//
// Events on stdout: {ready, port, publicKey, relayKey, relayAddr},
// {event: 'open', remote}, {event: 'done', bytes, ok, remote}.

const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const relay = require('blind-relay')
const b4a = require('b4a')
const readline = require('readline')
const Holepuncher = require('hyperdht/lib/holepuncher')

const CHUNK = b4a.alloc(16384)
for (let i = 0; i < CHUNK.length; i++) CHUNK[i] = i & 0xff

let beginPunch
const transferStarted = new Promise(resolve => { beginPunch = resolve })
const analyze = Holepuncher.prototype.analyze
Holepuncher.prototype.analyze = async function (...args) {
  // Hold only the test's direct path until relay application data is flowing.
  await transferStarted
  return analyze.apply(this, args)
}

function expectedByte (offset) {
  const within = offset % CHUNK.length
  return within < 8 ? Number((BigInt(Math.floor(offset / CHUNK.length)) >> BigInt(within * 8)) & 255n) : within & 255
}

function chunk (index) {
  const data = b4a.from(CHUNK)
  data.writeBigUInt64LE(BigInt(index), 0)
  return data
}

function remoteOf (conn) {
  const raw = conn.rawStream
  return raw ? { host: raw.remoteHost, port: raw.remotePort } : null
}

function emit (obj) {
  console.log(JSON.stringify(obj))
}

async function main () {
  const mode = process.argv[2]
  const noPunch = process.argv.includes('--no-punch')
  const testnet = await createTestnet(5)

  const relayDht = testnet.createNode({ firewalled: false })
  await relayDht.fullyBootstrapped()
  const relayServer = new relay.Server({
    createStream (streamOpts) {
      return relayDht.rawStreams.add(streamOpts)
    }
  })
  const relayKeyPair = DHT.keyPair()
  const relayHop = relayDht.createServer(socket => {
    relayServer.accept(socket, { id: socket.remotePublicKey })
  })
  await relayHop.listen(relayKeyPair)
  const relayAddr = relayDht.address()

  const dht = testnet.createNode({ firewalled: true, quickFirewall: false })
  await dht.fullyBootstrapped()
  const keyPair = DHT.keyPair()

  let swarm = null
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  lines.on('close', async () => {
    if (swarm) await swarm.destroy()
    await testnet.destroy()
    process.exit(0)
  })

  if (mode === 'server') {
    const server = dht.createServer(
      { holepunch: () => !noPunch, shareLocalAddress: false },
      conn => {
        let bytes = 0
        conn.on('error', () => {})
        emit({ event: 'open', remote: remoteOf(conn) })
        conn.on('data', data => {
          beginPunch()
          bytes += data.length
          conn.write(data)
        })
        conn.on('end', () => {
          emit({ event: 'done', bytes, ok: true, remote: remoteOf(conn) })
          conn.end()
        })
      }
    )
    await server.listen(keyPair)
    emit({ ready: true, port: testnet.bootstrap[0].port, publicKey: b4a.toString(keyPair.publicKey, 'hex'), relayKey: b4a.toString(relayKeyPair.publicKey, 'hex'), relayAddr })
    return
  }

  if (mode === 'swarm-server') {
    const Hyperswarm = require('hyperswarm')
    swarm = new Hyperswarm({
      dht,
      keyPair,
      relayThrough: () => relayKeyPair.publicKey
    })
    swarm.on('connection', conn => {
      let bytes = 0
      conn.on('error', () => {})
      emit({ event: 'open', remote: remoteOf(conn) })
      conn.on('data', data => {
        if (beginPunch) beginPunch()
        bytes += data.length
        conn.write(data)
      })
      conn.on('end', () => {
        emit({ event: 'done', bytes, ok: true, remote: remoteOf(conn) })
        conn.end()
      })
    })
    await swarm.listen()
    emit({ ready: true, port: testnet.bootstrap[0].port, publicKey: b4a.toString(keyPair.publicKey, 'hex'), relayKey: b4a.toString(relayKeyPair.publicKey, 'hex'), relayAddr })
    return
  }

  if (mode === 'swarm-client') {
    // Hyperswarm's dial defaults permit a loopback LAN shortcut; test the real punch.
    const connect = dht.connect.bind(dht)
    dht.connect = (key, opts) => connect(key, { ...opts, localConnection: false, fastOpen: false })
    const Hyperswarm = require('hyperswarm')
    swarm = new Hyperswarm({
      dht,
      keyPair,
      relayThrough: () => relayKeyPair.publicKey
    })
    swarm.on('connection', conn => {
      conn.on('error', err => emit({ event: 'error', message: err.message }))
      emit({ event: 'open', remote: remoteOf(conn) })
      const maxChunks = 4096
      let sent = 0
      let tail = 0
      const pump = () => {
        while (true) {
          const r = remoteOf(conn)
          const left = r && (r.host !== relayAddr.host || r.port !== relayAddr.port)
          if (left) tail++
          if (sent >= maxChunks || tail > 8) {
            conn.end()
            return
          }
          if (!conn.write(chunk(sent++))) {
            conn.once('drain', pump)
            return
          }
        }
      }
      pump()
      let bytes = 0
      let ok = true
      conn.on('data', data => {
        if (beginPunch) beginPunch()
        for (let i = 0; i < data.length; i++) {
          if (data[i] !== expectedByte(bytes + i)) ok = false
        }
        bytes += data.length
      })
      conn.on('end', () => emit({ event: 'done', bytes, ok, remote: remoteOf(conn) }))
    })
    emit({ ready: true, port: testnet.bootstrap[0].port, publicKey: b4a.toString(keyPair.publicKey, 'hex'), relayKey: b4a.toString(relayKeyPair.publicKey, 'hex'), relayAddr })
    lines.on('line', line => {
      const serverKey = b4a.from(line.trim(), 'hex')
      swarm.joinPeer(serverKey)
      swarm.flush()
    })
    return
  }

  emit({ ready: true, port: testnet.bootstrap[0].port, publicKey: b4a.toString(keyPair.publicKey, 'hex'), relayKey: b4a.toString(relayKeyPair.publicKey, 'hex'), relayAddr })
  lines.on('line', line => {
    const conn = dht.connect(b4a.from(line, 'hex'), {
      keyPair,
      relayThrough: relayKeyPair.publicKey,
      localConnection: false,
      fastOpen: false
    })
    conn.on('error', err => emit({ event: 'error', message: err.message }))
    conn.on('open', () => {
      emit({ event: 'open', remote: remoteOf(conn) })
      const maxChunks = 4096
      let sent = 0
      let tail = 0
      const pump = () => {
        while (true) {
          const r = remoteOf(conn)
          const left = r && (r.host !== relayAddr.host || r.port !== relayAddr.port)
          if (left) tail++
          if (sent >= maxChunks || tail > 8) {
            conn.end()
            return
          }
          if (!conn.write(chunk(sent++))) {
            conn.once('drain', pump)
            return
          }
        }
      }
      pump()
    })
    let bytes = 0
    let ok = true
    conn.on('data', data => {
      beginPunch()
      for (let i = 0; i < data.length; i++) {
        if (data[i] !== expectedByte(bytes + i)) ok = false
      }
      bytes += data.length
    })
    conn.on('end', () => emit({ event: 'done', bytes, ok, remote: remoteOf(conn) }))
  })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
