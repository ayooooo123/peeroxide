'use strict'

const DHT = require('hyperdht')

async function main () {
  const dht = new DHT({ host: '127.0.0.1', bootstrap: [], ephemeral: false, firewalled: false, port: [0, 0] })
  try {
    await dht.fullyBootstrapped()
    await dht.ping({ host: '127.0.0.1', port: Number(process.argv[2]) })
  } finally {
    await dht.destroy()
  }
}

main().catch(err => { console.error(err); process.exitCode = 1 })
