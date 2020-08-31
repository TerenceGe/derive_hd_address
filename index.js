const { createHash } = require('crypto')

const bip32 = require('bip32')
const bech32 = require('bech32')
const bs58check = require('bs58check')

const ripemd160 = buffer => createHash('rmd160').update(buffer).digest()
const sha256 = buffer => createHash('sha256').update(buffer).digest()
const hash160 = buffer => ripemd160(sha256(buffer))

const publicKeyToAddress = (value, chain, options) => {
  switch (chain) {
    case 'bitcoin': {
      const isSegWit = options.isSegWit
      const isP2SH = options.isP2SH
      const isTestnet = options.isTestnet
      const mainPublicKeyHash = hash160(value)
      const scriptHashPrefix = isTestnet ? 'C4' : '05'
      const pubKeyHashPrefix = isTestnet ? '6F' : '00'
      const bech32Prefix = isTestnet ? 'tc' : 'bt'

      let address

      if (isSegWit) {
        if (isP2SH) {
          const redeemHash = hash160(Buffer.from('0014' + mainPublicKeyHash.toString('hex'), 'hex'))
          address = bs58check.encode(Buffer.from(scriptHashPrefix + redeemHash.toString('hex'), 'hex'))
        } else {
          const words = bech32.toWords(mainPublicKeyHash)
          words.unshift(0x00)
          address = bech32.encode(bech32Prefix, words)
        }
      } else {
        address = bs58check.encode(Buffer.from(pubKeyHashPrefix + mainPublicKeyHash.toString('hex'), 'hex'))
      }

      return address
    }
    default:
      throw new Error(`unsupported chain type ${chain}`)
  }
}

const network = {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: {
        public: 0x044a5262,
        private: 0x0488ade4, // need confirm
    },
    pubKeyHash: 111,
    scriptHash: 196,
    wif: 239,
}

let node = bip32.fromBase58('upub5DRdTWfz3NeZwd25HeQ2xMNjnYtYRfZzC6fEDjmPH2AwnxjvTrySjVApEiDufv68gqsZ7TCUcNfb1P4KLjNvZCTsPCaVb68SLedQwPKMLKR', network)

let publicKey = node.derivePath('0/0').publicKey
let address = publicKeyToAddress(publicKey, 'bitcoin', { isTestnet: true, isSegWit: true, isP2SH: true })
console.log(`m/49'/0'/0'/0/0 address:`, address)

let publicKey1 = node.derivePath('0/1').publicKey
let address1 = publicKeyToAddress(publicKey1, 'bitcoin', { isTestnet: true, isSegWit: true, isP2SH: true })
console.log(`m/49'/0'/0'/0/1 address:`, address1)
