const crypto = require('node:crypto')
const { semiKey, semiIV } = require('./config.json')

function semiEnc(data) {
    const cipher = crypto.createCipheriv('aes-256-cbc', semiKey, semiIV)
    let encrypted = cipher.update(data, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    return encrypted
}

function keypair(passkey) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: passkey
        }
    })
    return { publicKey, privateKey }
}

module.exports = {
    semiEnc,
    keypair
}