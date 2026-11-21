const UDX = require('udx-native')
const readline = require('readline')

const u = new UDX()
const socket = u.createSocket()
socket.bind(0, '127.0.0.1')

const LOCAL_ID = 31
const REMOTE_ID = 32

process.stdout.write(
  JSON.stringify({
    port: socket.address().port,
    localId: LOCAL_ID,
    remoteId: REMOTE_ID,
    version: require('udx-native/package.json').version
  }) + '\n'
)

const rl = readline.createInterface({ input: process.stdin })
rl.once('line', (line) => {
  const { port } = JSON.parse(line)
  const stream = u.createStream(LOCAL_ID)
  let exchanges = 0

  stream.connect(socket, REMOTE_ID, port, '127.0.0.1')
  process.stdout.write(JSON.stringify({ ready: true }) + '\n')

  stream.on('error', (err) => {
    process.stderr.write(`stream error: ${err.message}\n`)
  })

  stream.on('data', (data) => {
    exchanges++
    if (exchanges === 1) {
      stream.write(Buffer.from('node-first'))
      const packetsReceived = stream.packetsReceived
      const packetsTransmitted = stream.packetsTransmitted
      setTimeout(() => {
        process.stdout.write(
          JSON.stringify({
            idle: true,
            packetsReceived: stream.packetsReceived - packetsReceived,
            packetsTransmitted: stream.packetsTransmitted - packetsTransmitted
          }) + '\n'
        )
      }, 40_000)
    } else if (exchanges === 2) {
      stream.write(Buffer.from('node-second'))
    }
  })

  stream.on('end', () => stream.end())
  stream.on('close', () => {
    socket.close().then(() => process.exit(0))
  })
})
