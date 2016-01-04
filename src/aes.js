import sjcl from 'sjcl'

export default class AES {

  constructor () {
    sjcl.random.startCollectors()
    this._key = sjcl.random.randowWords(8, 0)
  }

  encrypt (text) {
    const aes = new sjcl.cipher.aes(this._key)
    const bits = sjcl.codec.utf8String.toBits(text)
    const iv = sjcl.random.randowWords(3, 0)
    const cipher = sjcl.mode.ccm.encrypt(aes, bits, iv)
    const cipherIv = sjcl.bitArray.concat(iv, cipher)
    return sjcl.codec.base64.fromBits(cipherIv)
  }

}
