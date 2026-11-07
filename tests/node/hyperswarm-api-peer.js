'use strict'

const Hyperswarm = require('hyperswarm')
const createTestnet = require('hyperdht/testnet')
const readline = require('readline')

async function main () {
  const testnet = await createTestnet(3)
  const makeListener = keyPair => {
    const swarm = new Hyperswarm({ dht: testnet.createNode({ firewalled: false }), keyPair })
    swarm.on('connection', socket => {
      socket.on('error', err => console.error(err))
      socket.write(Buffer.from('js-listener'))
    })
    return swarm
  }
  let listener = makeListener()
  const joiner = new Hyperswarm({ dht: testnet.createNode({ firewalled: false }) })
  joiner.on('connection', socket => {
    socket.on('error', err => console.error(err))
    socket.write(Buffer.from('js-joiner'))
  })
  await listener.listen()
  console.log(JSON.stringify({ port: testnet.bootstrap[0].port, publicKey: listener.keyPair.publicKey.toString('hex') }))
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  lines.on('line', async line => {
    if (line !== 'restart') return joiner.joinPeer(Buffer.from(line, 'hex'))
    const keyPair = listener.keyPair
    await listener.destroy({ force: true })
    listener = makeListener(keyPair)
    await listener.listen()
    console.log(JSON.stringify({ restarted: true }))
  })
  lines.on('close', async () => { await listener.destroy(); await joiner.destroy(); await testnet.destroy() })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
