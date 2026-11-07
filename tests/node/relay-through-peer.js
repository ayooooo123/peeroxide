'use strict'

// A JS blind-relay server plus an echo server that advertises
// `relayThrough`, on one local testnet. A peeroxide client connecting to the
// echo server must reach it through the relay.

const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const relay = require('blind-relay')
const b4a = require('b4a')

async function main () {
  const testnet = await createTestnet(3)

  // Blind-relay server (Node createStream → dht raw streams).
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

  // Echo server that forces its clients through the relay.
  const echoDht = testnet.createNode({ firewalled: false })
  await echoDht.fullyBootstrapped()
  const echoKeyPair = DHT.keyPair()
  const echo = echoDht.createServer(
    { relayThrough: relayKeyPair.publicKey },
    conn => {
      conn.on('error', () => {})
      conn.on('data', data => conn.write(data))
    }
  )
  await echo.listen(echoKeyPair)

  console.log(JSON.stringify({
    port: testnet.bootstrap[0].port,
    publicKey: b4a.toString(echoKeyPair.publicKey, 'hex'),
    relayKey: b4a.toString(relayKeyPair.publicKey, 'hex')
  }))

  process.stdin.resume()
  process.stdin.on('end', async () => { await testnet.destroy() })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
