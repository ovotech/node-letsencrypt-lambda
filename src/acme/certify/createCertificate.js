const generateRSAKeyPair = require('../../util/generateRSAKeyPair')
const newCertificate = require('./newCertificate')
const generateCSR = require('../../util/generateCSR')
const config = require('../../../config/default.json')
const saveFile = require('../../aws/s3/saveFile')
const AWS = require('aws-sdk')
AWS.config.update({region:'eu-west-1'})
const acm = new AWS.ACM()


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
      return saveCertificate({
        key: certInfo.key,
        keypair: domainKeypair,
        cert: certData.cert,
        issuerCert: certData.issuerCert
      }).then(() => {
        const params = {
          Certificate: new Buffer(certData.cert),
          PrivateKey: new Buffer(domainKeypair.privateKeyPem),
          CertificateChain: new Buffer(certData.issuerCert)
        };
        console.log(params);
        acm.importCertificate(params, function(err, data) {
          if (err) console.log(err, err.stack); // an error occurred
          else     console.log(data);           // successful response
        });
      })
   })
  )

module.exports = createCertificate
