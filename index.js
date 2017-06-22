'use strict'

const https      = require('https');
const fs         = require('fs');
const express    = require('express');
const bodyParser = require('body-parser'); 
const app        = express();
const webid      = require('webid')('tls');
const forge      = require('node-forge');
const asn1       = forge.asn1;
const pki        = forge.pki;
const path       = require('path');
const $rdf       = require('rdflib');

// HELPERS =================
var profileTemplate;
try {
    profileTemplate = fs.readFileSync('./static/profileTemplate.n3');
} catch(e) {
    console.log(e);
}
var genProfile = (uri, name, cert, prof) => {
    var FOAF = $rdf.Namespace('http://xmlns.com/foaf/0.1');
    var RDFS = $rdf.Namespace('http://www.w3.org/1999/02/22-rdf-syntax-ns#');
    var CERT = $rdf.Namespace('http://www.w3.org/ns/auth/cert#');
    var XSD  = $rdf.Namespace('http://www.w3.org/2001/XMLSchema#');
    var certModulus = CERT('modulus');
    // we need to add the modulus to the profile doc and the name
    var store = $rdf.graph();
    try {
        $rdf.parse(prof.toString(), store, uri, 'text/n3');  
    } catch(e) {
        console.log(e);
        return;
    }

    var me = $rdf.sym(uri);
    //store.add(me, FOAF('name'), name);  
    //store.add(me, RDFS('label'), new Date().toDateString());
    var pk = cert.publicKey;
    //store.add(me, CERT('modulus'), pk.n.toString(16) + '^^xsd:hexBinary');
    //store.add(me, CERT('exponent'), pk.e.toString());

    /*
    store.removeMany(me, FOAF('name'));
    store.add(me, FOAF('name'), name);
    store.removeMany(me, RDFS('label'));
    store.add(me, RDFS('label'), new Date().toDateString());
    store.removeMany(me, CERT('modulus'));
    store.add(me, CERT('modulus'), $rdf.lit(pk.n.toString(16), null, XSD('hexBinary')));
    store.removeMany(me, CERT('exponent'));
    store.add(me, CERT('exponent'), pk.e.toString());
    */

    var key = $rdf.sym(uri + '#public_key');
    const mod = store.statementsMatching(
            key, 
            CERT('modulus'), 
            undefined);
    const exp = store.statementsMatching(
            undefined, 
            CERT('exponent'), 
            undefined);
    const label = store.statementsMatching(
            undefined, 
            RDFS('label'), 
            undefined);

    //console.log(me);
    console.log(mod);

    // Serialize the store into the modified document
    $rdf.serialize(me, store, undefined, 'text/turtle', (err, result) => {
        if (!err) {
            console.log(result);
        } else {
            console.log(err);
        }
    }); 

    return null;
};
// =========================

// SET UP THE APP ==========
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'static')));
// =========================

// SET UP THE SERVER =======
const PORT = 3000;
const opts = {
    cert: fs.readFileSync('./certs/server-crt.pem'),
    key:  fs.readFileSync('./certs/server-key.pem'),
    rejectUnauthorized: false
};
var server = https.createServer(opts, app);
server.listen(PORT, () => {
    console.log('Application is listening on port ' + PORT);
});
// =========================

// ROUTING =================
app.get('/', (req, res, next) => {
    // Serve the index.html
    res.sendFile('index.html');
});

app.post('/webid-get', (req, res, next) => {
    // generate the webid
    //<keygen>
    var uri = req.body.url;
    var name = req.body.name.replace(/ /,'').toLowerCase();
    if (uri.charAt(uri.length - 1) === '/') {
        uri += name;
    } else {
        uri += '/' + name;
    }

    console.log("uri: ", uri);
    const options = {
        spkac: req.body.spkac.replace(/\r\n/g,''),
        agent: uri 
    };

    webid.generate(options, (err, cert) => {
        if (!err && cert) {
            const der = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
            // generate the profile
            genProfile(uri, name, cert, profileTemplate);
            // send the cert back to the browser
            res.set('Content-Type', 'application/x-x509-user-cert');
            res.send(Buffer(der, 'binary'));
        } else {
            console.log(err);
            res.send("An error occured");
        }
    });
});
// =========================
