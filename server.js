const cluster = require('cluster');
const fs = require('fs')
const tls = require('tls')

Array.prototype.random = function () {
    return this[Math.floor((Math.random() * this.length))];
}

let config = JSON.parse(fs.readFileSync('config.json'))

let certificateRoute = {}

let defaultCertificate = { ...{
        SNICallback: function (domain, cb) {
            let targetRoute = Object.values(config.routing).find(o => o.host.includes(domain) && o.secure)
            if (targetRoute) {
                cb(null, tls.createSecureContext(targetRoute.secure))
            } else {
                cb(null, null)
            }
        }
    },
    ...config.defaultCertificate
}


var greenlock = require('greenlock').create({
    version: 'draft-12',
    server: 'https://acme-v02.api.letsencrypt.org/directory',
    configDir: '/tmp/acme/etc'
});


function letsEncrypt(domains, callback) {
    var opts = {
        domains: domains,
        email: 'ruby.aqour@gmail.com',
        agreeTos: true // Accept Let's Encrypt v2 Agreement
            ,
        communityMember: true // Help make Greenlock better by submitting
        // stats and getting updates
    };
    greenlock.register(opts).then(function (certs) {
        callback(null, certs)
        // privkey, cert, chain, expiresAt, issuedAt, subject, altnames
    }, function (err) {
        callback(err, null)
    });
}

// Workers can share any TCP connection
// In this case it is an HTTP server
var proxy = require('http-proxy-middleware');
var express = require('express')
var app = express()
var http = require('http')
var https = require('https')
var bodyParser = require('body-parser')


app.use('/', greenlock.middleware());
app.use((req, res, next) => {   
     let proxyTarget = decideProxyTarget(req.headers.host, !!req.socket.server.key)

    proxy({
        target: proxyTarget,
        ws: false,
        changeOrigin: proxyTarget.sendHost || true
    })(req, res, next)


});

let upgradeFn = (req, c1, c2) => {
    let proxyTarget = decideProxyTarget(req.headers.host, !!req.socket.server.key)

    proxy({
        target: proxyTarget,
        changeOrigin: proxyTarget.sendHost || true
    }).upgrade(req, c1, c2)

};
var httpServer = http.createServer(app).listen(80);
var httpsServer = https.createServer(defaultCertificate, app).listen(443);
httpServer.on('upgrade', upgradeFn)
httpsServer.on('upgrade', upgradeFn)
function decideProxyTarget(host, isSecure) {

    if (!Object.values(config.routing).find(o => o.host.includes(host))) {
        throw new Error('No such host')
    }
    let targetRoute = JSON.parse(JSON.stringify(Object.values(config.routing).find(o => o.host.includes(host))))
    let proxyTarget
    let httpTargets = []
    let httpsTargets = []
    targetRoute.target.forEach((v) => {
        if (v.startsWith('https://')) {
            httpsTargets.push(v)
        } else {
            httpTargets.push(v)
        }
    })
    if (httpsTargets.length > 0 && isSecure) {
        // https 타겟 O, http 타겟 ?, https로 연결 -> https 타겟으로 연결
        proxyTarget = httpsTargets.random()
    } else if (httpTargets.length > 0 && !isSecure) {
        // https 타겟 X, http 타겟 O, http로 연결 -> http 타겟으로 연결
        proxyTarget = httpTargets.random()
    } else if (httpsTargets.length > 0 && !isSecure) {
        // http 타겟 X, https 타겟 O, http로 연결 -> https 타겟으로 연결
        proxyTarget = httpsTargets.random()
    } else if (httpTargets.length > 0 && isSecure) {
        // http 타겟 O, https 타겟 X, https로 연결 -> http 타겟으로 연결
        proxyTarget = httpTargets.random()
    } else {
        throw new Error('No servers to handle your request.')
    }
    return proxyTarget

}


// API Server
// Require express and create an instance of it
var apiapp = express();
var uuid = require('uuid');

apiapp.use(bodyParser.json())
apiapp.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,PUT,DELETE')
    res.setHeader('Access-Control-Expose-Headers', 'Location')
    next()
})
// on the request to root (localhost:3000/)
apiapp.get('/certificate/letsencrypt/:domain', function (req, res) {
    letsEncrypt(req.params.domain.split(','), (err, certs) => {
        if (err) {
            res.status(500)
            res.json({
                'result': 'failed',
                'error': err
            });
        } else {
            res.json({
                'result': 'success',
                'certs': certs
            });
        }
    })
});

apiapp.get('/routes', (req, res) => {
    res.json({
        'result': 'success',
        'data': config.routing
    })
})

apiapp.get('/routes/:routeId', (req, res) => {
    if (config.routing[req.params.routeId]) {
        res.json(config.routing[req.params.routeId])
    } else {
        res.sendStatus(404)
    }
})

apiapp.post('/routes', (req, res) => {
    // Check Problem
    let newData = req.body
    let dataUUID = uuid.v4()
    // Check host conflict
    let isConflict = false
    newData.host.forEach((host) => {
        if (Object.values(config.routing).find(o => o.host.includes(host))) {
            isConflict = true;
        }
    })
    if (isConflict) {
        res.sendStatus(409)
        return
    }
    config.routing[dataUUID] = newData
    saveConfig()
    res.setHeader('Location', '/routes/' + dataUUID)
    res.sendStatus(201)
})

apiapp.patch('/routes/:routeId', (req, res) => {
    let newData = req.body
    let conflict = false
    if (config.routing[req.params.routeId]) {
        if (newData.host) {
            // Host 중복 체크
            newData.host.forEach((host) => {
                if (Object.keys(config.routing).find(o => config.routing[o].host.includes(host) && o != req.params.routeId)) {
                    conflict = true
                }
            })
        }
        if (conflict) {
            res.sendStatus(409)
            return
        }
        let currentData = config.routing[req.params.routeId]
        config.routing[req.params.routeId] = { ...currentData,
            ...newData
        }
        saveConfig()
        res.json({
            'status': 'ok'
        })
    } else {
        res.sendStatus(404)
    }
})

apiapp.delete('/routes/:routeId', (req, res) => {
    if (config.routing[req.params.routeId]) {
        delete config.routing[req.params.routeId]
        saveConfig()
        res.sendStatus(200)
    } else {
        res.sendStatus(404)
    }
})

apiapp.use(express.static('web/'))
apiapp.use((req, res, next) => {
    fs.createReadStream('web/index.html').pipe(res)
})

apiapp.listen(8909, function () {
    console.log('API Access Path: 127.0.0.25:8909');
    console.log('Access to it directly or set up reverse proxy with this ip')
});

function saveConfig(cb) {
    if (!cb) cb = () => {}
    fs.writeFile('config.json', JSON.stringify(config), cb)
}