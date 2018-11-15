const cluster = require('cluster');
const fs = require('fs')
const tls = require('tls')

Array.prototype.random = function () {
    return this[Math.floor((Math.random()*this.length))];
  }

let config = JSON.parse(fs.readFileSync('config.json'))

let certificateRoute = {}

let defaultCertificate = {...{
    SNICallback: function (domain, cb) {
        let targetRoute = Object.values(config.routing).find(o => o.host.includes(domain) && o.secure)
        if(targetRoute){
            cb(null, tls.createSecureContext(targetRoute.secure))
        } else {
            cb(null, null)
        }
    }
}, ...config.defaultCertificate}


var greenlock = require('greenlock').create({
    version: 'draft-12'
  , server: 'https://acme-staging-v02.api.letsencrypt.org/directory'
  , configDir: '/tmp/acme/etc'
  });
  

function letsEncrypt(domains, callback){
    var opts = {
        domains: domains
      , email: 'ruby.aqour@gmail.com'
      , agreeTos: true                  // Accept Let's Encrypt v2 Agreement
      , communityMember: true           // Help make Greenlock better by submitting
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
      let targetRoute = Object.values(config.routing).find(o => o.host.includes(req.headers.host))
      if(!targetRoute){
          res.status(400).send('No such route')
          res.end('No such route')
      } else {
          if(req.url == '/cdn-cgi/trace'){
              if(targetRoute.lockDetails){
                  res.status(401).send('Tried to access hidden route')
              } else{
                  if(targetRoute.secure){
                      targetRoute.secure.key = "####Censored by nProxy####";
                  }
                  res.json(targetRoute)
              }
          } else {
              proxy({
                  target: targetRoute.target.random(), 
                  ws: targetRoute.websocket || true,
                  changeOrigin: targetRoute.sendHost || true
              })(req, res, next)
          }
      }
  
  });
  var httpServer = http.createServer(app).listen(80);
  var httpsServer = https.createServer(defaultCertificate, app).listen(443);
  

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
        if(err){
            res.status(500)
            res.json({'result': 'failed', 'error': err});
        } else {
            res.json({'result': 'success', 'certs': certs});
        }
    })
});

apiapp.get('/routes', (req, res) => {
    res.json({'result': 'success', 'data': config.routing})
})

apiapp.get('/routes/:routeId', (req, res) => {
    if(config.routing[req.params.routeId]){
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
        if(Object.values(config.routing).find(o => o.host.includes(host))){
            isConflict=true;
        }
    })
    if(isConflict){
        res.sendStatus(409)
            return
    }
    config.routing[dataUUID] = newData
    saveConfig()
    res.setHeader('Location','/routes/' + dataUUID)
    res.sendStatus(201)
})

apiapp.patch('/routes/:routeId', (req, res) => {
    let newData = req.body
    let conflict = false
    if(config.routing[req.params.routeId]){
        if(newData.host){
            // Host 중복 체크
            newData.host.forEach((host) => {
                if(Object.keys(config.routing).find(o => config.routing[o].host.includes(host) && o != req.params.routeId)){
                    conflict = true
                }
            })
        }
        if(conflict){
            res.sendStatus(409)
                    return
        }
        let currentData = config.routing[req.params.routeId]
        config.routing[req.params.routeId] = {...currentData, ...newData}
        saveConfig()
        res.json({'status': 'ok'})
    } else {
        res.sendStatus(404)
    }
})

apiapp.delete('/routes/:routeId', (req, res) => {
    if(config.routing[req.params.routeId]){
        delete config.routing[req.params.routeId]
        saveConfig()
        res.sendStatus(200)
    } else {
        res.sendStatus(404)
    }
})

apiapp.use(express.static('web/'))
apiapp.use((req, res, next) =>{
fs.createReadStream('web/index.html').pipe(res)
})

apiapp.listen(8909, function () {
    console.log('API Access Path: 127.0.0.25:8909');
    console.log('Access to it directly or set up reverse proxy with this ip')
});

function saveConfig(cb){
if(!cb) cb = ()=>{}
fs.writeFile('config.json', JSON.stringify(config), cb)
}