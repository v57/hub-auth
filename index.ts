import { Keychain } from './keychain'
import { Service } from 'hub-service'

const keychain = new Keychain()
await keychain.load()

new Service().start()
