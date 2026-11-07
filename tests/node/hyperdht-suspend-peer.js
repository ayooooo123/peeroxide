'use strict'

const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')

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
  console.log(JSON.stringify({
    port: testnet.bootstrap[0].port,
    dhtPort: dht.address().port,
    publicKey: keyPair.publicKey.toString('hex')
  }))
  process.stdin.resume()
  process.stdin.on('end', async () => { await testnet.destroy() })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
