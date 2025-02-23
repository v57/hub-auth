import { Keychain } from './keychain'
import { Service } from 'hub-service'

const keychain = new Keychain()
await keychain.load()

new Service()
  .post('auth/verify', body => keychain.verify(body))
  .post('auth/permissions/add', ({ key, permissions }) => keychain.addPermissions(key, permissions))
  .post('auth/permissions/remove', ({ key, permissions }) => keychain.removePermissions(key, permissions))
  .post('auth/keys/add', key => keychain.add(key))
  .post('auth/keys/remove', key => keychain.remove(key))
  .start()
