'use strict'

// Node clients for the Rust peer-firewall interop test. Prints the testnet
// port and two client keys; on a server key line it dials with the refused
// key, then with the allowed key, and prints one JSON line per outcome.

const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const readline = require('readline')

function dial (dht, serverKey, keyPair) {
  return new Promise(resolve => {
    const conn = dht.connect(serverKey, { keyPair })
    conn.on('error', err => resolve({ error: err.code || err.message }))
    conn.on('open', () => conn.write(Buffer.from('allowed-client')))
    conn.on('data', data => {
      resolve({ data: data.toString() })
      conn.destroy()
    })
  })
}

async function main () {
  const testnet = await createTestnet(3)
  const dht = testnet.createNode()
  await dht.fullyBootstrapped()
  const allowed = DHT.keyPair()
  const refused = DHT.keyPair()
  console.log(JSON.stringify({
    port: testnet.bootstrap[0].port,
    allowed: allowed.publicKey.toString('hex'),
    refused: refused.publicKey.toString('hex')
  }))
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  lines.on('line', async line => {
    const serverKey = Buffer.from(line, 'hex')
    console.log(JSON.stringify({ refused: await dial(dht, serverKey, refused) }))
    console.log(JSON.stringify({ allowed: await dial(dht, serverKey, allowed) }))
  })
  lines.on('close', async () => { await testnet.destroy() })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
