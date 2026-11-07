'use strict'

const DHT = require('hyperdht')

async function main () {
  const dht = new DHT({ host: '127.0.0.1', bootstrap: [], ephemeral: false, firewalled: false, port: [0, 0] })
  await dht.fullyBootstrapped()
  const raw = dht.createRawStream()
  raw.on('error', err => { console.error(err); process.exitCode = 1 })
  raw.on('data', data => raw.write(data))
  raw.connect(dht.io.serverSocket, Number(process.argv[3]), Number(process.argv[2]), '127.0.0.1')
  process.stdout.write(JSON.stringify({ id: raw.id, port: dht.io.serverSocket.address().port }) + '\n')
}

main().catch(err => { console.error(err); process.exitCode = 1 })
