'use strict'

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
    conn.on('data', data => conn.write(data))
  })
  await server.listen(keyPair)
  console.log(JSON.stringify({ port: testnet.bootstrap[0].port, publicKey: keyPair.publicKey.toString('hex') }))
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  lines.on('line', line => {
    const key = Buffer.from(line, 'hex')
    const conn = dht.connect(key)
    conn.on('error', err => { console.error(err); process.exitCode = 1 })
    conn.on('open', () => conn.write(Buffer.from('js-client')))
    conn.on('data', data => console.log(JSON.stringify({ data: data.toString() })))
  })
  lines.on('close', async () => { await testnet.destroy() })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
