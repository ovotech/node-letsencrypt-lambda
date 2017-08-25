const generateRSAKeyPair = require('../../util/generateRSAKeyPair')
const newCertificate = require('./newCertificate')
const generateCSR = require('../../util/generateCSR')
const config = require('../../../config/default.json')
const saveFile = require('../../aws/s3/saveFile')
const acm = new AWS.ACM();

const saveCertificate = (data) =>
  saveFile(
    config['s3-cert-bucket'],
    config['s3-folder'],
    `${data.key}.json`,
    JSON.stringify({
      key: data.keypair,
      cert: data.cert,
      issuerCert: data.issuerCert
    })
  )

const createCertificate = (certUrl, certInfo, acctKeyPair) => (authorizations) =>
  generateRSAKeyPair()
  .then((domainKeypair) =>
    generateCSR(domainKeypair, certInfo.domains)
    .then(newCertificate(acctKeyPair, authorizations, certUrl))
    .then((certData) => {
      const params = {
        Certificate: new Buffer(certData.cert)
        PrivateKey: new Buffer(certInfo.key)
      };
      acm.importCertificate(params, function(err, data) {
        if (err) console.log(err, err.stack); // an error occurred
        else     console.log(data);           // successful response
      });
      return saveCertificate({
        key: certInfo.key,
        keypair: domainKeypair,
        cert: certData.cert,
        issuerCert: certData.issuerCert
      })
    }
    )
  )

module.exports = createCertificate
