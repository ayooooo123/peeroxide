'use strict'

// Hyperdht server for the connection keep-alive interop test.
// Prints {port, publicKey}; for each connection prints {data, rawBytesRead}
// on data (and echoes it back) and {error} on error. A "status" line on
// stdin prints {status, errors, rawBytesRead, rawBytesWritten} of the last
// connection.

const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const readline = require('readline')

async function main () {
  const testnet = await createTestnet(3)
  const dht = testnet.createNode({ firewalled: false })
  await dht.fullyBootstrapped()
  const keyPair = DHT.keyPair()
  const errors = []
  let last = null
  const server = dht.createServer(conn => {
    last = conn
    conn.on('error', err => {
      errors.push(String(err && err.message))
      console.log(JSON.stringify({ error: String(err && err.message) }))
    })
    conn.on('data', data => {
      console.log(JSON.stringify({ data: data.toString(), rawBytesRead: conn.rawBytesRead }))
      conn.write(Buffer.from('js-reply:' + data.toString()))
    })
  })
  await server.listen(keyPair)
  console.log(JSON.stringify({ port: testnet.bootstrap[0].port, publicKey: keyPair.publicKey.toString('hex') }))
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  lines.on('line', line => {
    if (line !== 'status') return
    console.log(JSON.stringify({
      status: last !== null && !last.destroyed,
      errors,
      rawBytesRead: last ? last.rawBytesRead : 0,
      rawBytesWritten: last ? last.rawBytesWritten : 0
    }))
  })
  lines.on('close', async () => { await testnet.destroy() })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
