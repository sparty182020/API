const express = require('express')
const crypto = require('node:crypto')
const path = require('path')
const util = require('./util-fuctions')
const ccf = require('./crypto')
const { key, adminLogin } = require('./config.json')

const app = express();
const PORT = 8081
app.use(express.json())

// Homepage
app.all('/', (req, res, next) => {
    sendHTMLFile('index.html', res, 200)
})

// Authentication
app.all('*', (req, res, next) => {
    if (!req.headers.authorization) { res.status(401).end().destroy(); return }
    const auth = Buffer.from(req.headers.authorization.slice(6), 'base64').toString('utf-8')
    const [username, password] = auth.split(':')
    if (username == adminLogin.username && password == adminLogin.password) {
        next()
    } else {
        sendHTMLFile('401.html', res, 401)
    }
})

// Method Testing
app.all('*', (req, res, next) => {
    const uriMethods = require('./valid_methods.json')
    const uri = req.path
    const method = req.method
    let v;
    uriMethods[uri].forEach((data) => {
        if (data == method) {
            v = true
            next()
        }
    })
    if (!v) {
        sendHTMLFile('400.html', res, 400)
    }
})

app.post('/login/', (req, res) => {
    const { user_data } = require('./valid_hashes.json')
    const { method, data, digest } = req.body;
    let m;
    if (!method || !data || !digest) {
        res.status(400).send(util.failedStatus('Missing data'));
        return;
    }
    switch (method) {
        case 'sha512':
        case 'sha-512':
        case '512':
            m = 'sha512';
            break;
        case 'sha256':
        case 'sha-256':
        case '256':
            m = 'sha256';
            break;
        default:
            res.status(400).send('Invalid method')
            return;
    }
    if (!data.usn || !data.pwd) {
        res.status(400).send(util.failedStatus('Missing login data'));
        return;
    }
    switch (digest) {
        case 'hex':
        case 'base64':
        case 'ascii':
            break
        default:
            res.status(400).send('Invalid digest')
            return;
    }
    const ld = `${data.usn}:${data.pwd}`;
    const enc = crypto.createHmac(m, key).update(ld).digest(digest);
    let f;
    user_data.forEach((data, i) => {
        if (enc == data.hash) {
            res.status(200).send({
                found: true,
                user: data.username,
                userid: data.id,
                timestamp: Date.now(),
                res_uuid: crypto.randomUUID()
            });
            f = true;
        }
    })
    if (!f) {
        res.status(403).send(
            util.failedStatus('Login Not Found', {
                found: false,
                timestamp: Date.now(),
                res_uuid: crypto.randomUUID()
            }))
    }
})

app.listen(PORT, () => {
    console.log(
        `Server is listening at localhost:${PORT}, 127.0.0.1:${PORT}, and sparty18api.ddnsfree.com:${PORT}`
    )
})

function sendHTMLFile(filename, res, status) {
    var options = {
        root: path.join(__dirname, 'html'),
        dotfiles: 'deny',
        headers: {
            'x-timestamp': Date.now(),
            'x-sent': true
        }
    }
    res.status(status).sendFile(filename, options, function (e) { })
}