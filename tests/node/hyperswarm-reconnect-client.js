'use strict'

// Node hyperswarm client for `peeroxide/tests/reconnect_after_close.rs`:
// connects to a Rust swarm server on a topic, destroys the connection and
// reconnects, reporting each step as a JSON line on stdout.
//
// Usage:
//   node hyperswarm-reconnect-client.js
//
// stdout:
//   {"ready":true,"bootstrap":[{"host":"127.0.0.1","port":N},...],"publicKey":"<hex>"}
//   {"event":"joined"}
//   {"event":"connection","n":1,"client":true}
//   {"event":"reconnected","n":2}
//
// stdin commands (one JSON object per line):
//   {"cmd":"join","topic":"<hex>"}   join as client and start connecting
//   {"cmd":"shutdown"}               exit

const createTestnet = require('hyperdht/testnet')
const Hyperswarm = require('hyperswarm')
const b4a = require('b4a')
const readline = require('readline')

function send (msg) {
  process.stdout.write(JSON.stringify(msg) + '\n')
}

async function main () {
  const testnet = await createTestnet(3)

  // Reachable and persistent: it stores the Rust server's announce and hands
  // it to the client, so the handshake goes straight to the server.
  const node = testnet.createNode({ ephemeral: false, firewalled: false })
  await node.fullyBootstrapped()

  const swarm = new Hyperswarm({ dht: node })

  let connections = 0
  swarm.on('connection', (socket, info) => {
    connections++
    send({ event: 'connection', n: connections, client: info.client })

    if (connections === 1) {
      // Drop it like a client that lost its connection; the swarm redials.
      setTimeout(() => socket.destroy(), 300)
      return
    }

    send({ event: 'reconnected', n: connections })
    // Give Rust time to receive the accepted connection before closing the peer.
    setTimeout(() => swarm.destroy().then(() => process.exit(0)), 200)
  })

  send({
    ready: true,
    bootstrap: testnet.bootstrap,
    publicKey: b4a.toString(swarm.keyPair.publicKey, 'hex')
  })

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  rl.on('line', (line) => {
    let msg
    try {
      msg = JSON.parse(line)
    } catch {
      return
    }
    if (msg.cmd === 'join') {
      const topic = b4a.from(msg.topic, 'hex')
      swarm.join(topic, { server: false, client: true }).flushed().then(() => {
        send({ event: 'joined' })
      })
    } else if (msg.cmd === 'shutdown') {
      process.exit(0)
    }
  })
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
