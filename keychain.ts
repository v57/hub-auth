import { createHmac } from 'crypto'

export class Keychain {
  keys: any = {}
  async load() {
    try {
      const keys: Key[] = await Bun.file('keychain.json').json()
      for (const key of keys) {
        this.keys[this.hashKey(key)] = key
      }
    } catch {}
  }
  async save() {
    await Bun.file('keychain.json').write(JSON.stringify(this.keys, null, 2))
  }
  async add(key: Key) {
    this.keys[this.hashKey(key)] = key
    await this.save()
  }
  async remove(key: string) {
    delete this.keys[key]
    await this.save()
  }
  async addPermissions(key: string, permissions: string[]) {
    if (permissions.length === 0) return
    const k: Key | undefined = this.keys[key]
    if (!k) return
    const set = new Set(k.permissions)
    let didAdd = false
    permissions.forEach(p => {
      if (!set.has(p)) {
        set.add(p)
        k.permissions.push(p)
        didAdd = true
      }
    })
    if (didAdd) await this.save()
  }
  async removePermissions(key: string, permissions: string[]) {
    let didRemove = false
    const k: Key | undefined = this.keys[key]
    if (!k) return
    permissions.forEach(p => {
      const i = k.permissions.findIndex(a => a === p)
      if (i >= 0) {
        k.permissions.splice(i, 1)
        didRemove = true
      }
    })
    if (didRemove) await this.save()
  }
  // Returns permissions list
  verify(data: string): string[] {
    const parts = data.split('.')
    if (parts.length < 3) {
      return []
    }
    const [t, id, hash, time] = parts
    if (t === 'hmac') {
      const keyInfo: Key = this.keys[`${t}.${hash}`]
      if (keyInfo && this.verifyHmac(id, hash, time, keyInfo.key)) {
        return keyInfo.permissions
      }
    }
    return []
  }
  private hashKey(key: Key) {
    const hash = new Bun.SHA256().update(key.key).digest('hex')
    return `${key.type}.${hash}`
  }
  private verifyHmac(id: string, hash: string, time: string, key: string) {
    let data = id
    if (time) {
      const s = parseInt(time, 36)
      const now = Math.round(new Date().getTime() / 1000)
      if (s <= now) throw 'authorization expired'
      data = `${id}/${time}`
    }
    const expected = createHmac('sha256', key).update(data).digest('base64')
    if (hash !== expected) throw 'authorization failed'
    return id
  }
}

interface Key {
  key: string
  type: 'hmac'
  permissions: string[]
}
