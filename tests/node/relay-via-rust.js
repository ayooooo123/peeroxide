'use strict'

// Two JS peers relayed through a peeroxide blind-relay server.
// argv: <bootstrapPort> <relayPublicKeyHex>
//
// Same recipe as hyperdht's test/relaying.js "server side, client abort
// notifies remote": both peers stay firewalled, the server shares no LAN
// address, and the client skips fast-open, the same-host shortcut and the
// holepunch, so the relay is the only path. `relayed` reports whether the
// echo really arrived from the relay's socket.

const DHT = require('hyperdht')
const b4a = require('b4a')

async function main () {
  const bootstrapPort = Number(process.argv[2])
  const relayKey = b4a.from(process.argv[3], 'hex')
  const bootstrap = [{ host: '127.0.0.1', port: bootstrapPort }]

  const serverDht = new DHT({ bootstrap, host: '127.0.0.1', firewalled: true, quickFirewall: false })
  const clientDht = new DHT({ bootstrap, host: '127.0.0.1', firewalled: true, quickFirewall: false })
  await serverDht.fullyBootstrapped()
  await clientDht.fullyBootstrapped()

  const keyPair = DHT.keyPair()
  const server = serverDht.createServer({ relayThrough: relayKey, shareLocalAddress: false }, conn => {
    conn.on('error', () => {})
    conn.on('data', data => conn.write(data))
  })
  await server.listen(keyPair)

  const conn = clientDht.connect(keyPair.publicKey, {
    fastOpen: false,
    localConnection: false,
    holepunch: () => false
  })
  conn.on('error', err => {
    console.log(JSON.stringify({ error: err.message }))
    process.exitCode = 1
  })
  conn.on('open', () => conn.write(b4a.from('js-through-rust-relay')))
  conn.on('data', data => {
    const relayed = conn.rawStream.remotePort === bootstrapPort
    console.log(JSON.stringify({ data: b4a.toString(data), relayed }))
  })

  process.stdin.resume()
  process.stdin.on('end', async () => {
    await server.close()
    await serverDht.destroy()
    await clientDht.destroy()
  })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
