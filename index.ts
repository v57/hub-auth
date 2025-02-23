import { Keychain } from './keychain'
import { Service } from 'hub-service'

const keychain = new Keychain()
await keychain.load()

new Service().post('auth/verify', body => keychain.verify(body)).start()
