'use strict'

// Mirrors private-overlay.js: a raw stream is created with a firewall that
// only accepts the control connection's remote, and connected later over that
// control connection with `HyperDHT.connectRawStream`.

const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const readline = require('readline')

async function main () {
  const testnet = await createTestnet(3)
  const dht = testnet.createNode({ firewalled: false })
  await dht.fullyBootstrapped()
  const keyPair = DHT.keyPair()

  const server = dht.createServer(conn => {
    conn.on('error', err => console.error(err))
    const rc = conn.rawStream
    const firewall = (_s, port, host) => port !== rc.remotePort || host !== rc.remoteHost
    const raw = dht.createRawStream({ framed: false, firewall })
    raw.on('error', err => console.error(err))
    conn.write(JSON.stringify({ id: raw.id }))
    conn.once('data', data => {
      const { id } = JSON.parse(data.toString())
      DHT.connectRawStream(conn, raw, id)
      raw.on('data', chunk => raw.write(chunk))
      conn.write(JSON.stringify({ connected: true }))
    })
  })
  await server.listen(keyPair)

  console.log(JSON.stringify({
    port: testnet.bootstrap[0].port,
    publicKey: keyPair.publicKey.toString('hex')
  }))
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  lines.on('close', async () => { await testnet.destroy() })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
