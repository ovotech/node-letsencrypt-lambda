import config from '../../../config/default.json'
import readFile from '../../aws/s3/readFile'
import createDomain from './createDomain'

const getDomainCertificate = (certUrl, domain, userKeypair) => (authorizations) =>
  readFile(
    config['s3-cert-bucket'],
    'letsencrypt',
    `letsencrypt_${domain}.json`
  )
  .then((data) => Promise.resolve(JSON.parse(data.Body.toString())))
  .catch((e) => {
    console.log(`Creating domain since couldn't read letsencrypt/letsencrypt_${domain}.json`)
    return createDomain(certUrl, authorizations, domain, userKeypair)
  })

module.exports = getDomainCertificate