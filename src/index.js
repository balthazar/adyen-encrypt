import sjcl from 'sjcl'

export default class AdyenEncrypt {

  constructor (key, opts = {}) {

    if (!key) { throw new Error('No key provided.') }

    this._key = key
    this._opts = opts

    this._encryptVersion = '0_1_15'

    sjcl.random.startCollectors()

    if (typeof this._opts.numberIgnoreNonNumeric === 'undefined') {
      this._opts.numberIgnoreNonNumeric = true
    }

    if (typeof this._opts.cvcIgnoreFornumber !== 'undefined') {
      delete this._opts.cvcIgnoreFornumber
    }

    if (typeof this._opts.cvcIgnoreBins === 'string') {
      const binsToIgnore = []

      this._opts.cvcIgnoreBins.replace(/\d+/g, function (m) {
        if (m.length > 0 && !isNaN(parseInt(m, 10))) {
          binsToIgnore.push(m)
        }
        return m
      })

      if (binsToIgnore.length > 0) {
        this._opts.cvcIgnoreFornumber = new RegExp('^\\s*(' + binsToIgnore.join('|') + ')')
      }

    } else if (typeof this._opts.cvcIgnoreBins !== 'undefined') {
      delete this._opts.cvcIgnoreBins
    }

  }

  /**
   * Encrypt the card data
   *
   * @param data {Object}
   * @param data.number {String}
   * @param data.cvc {String}
   * @param data.expiryMonth {String}
   * @param data.expiryYear {String}
   * @param data.holderName {String}
   * @returns {String}
   */
  encrypt (data) {

    const validations = {
      number: data.number || '',
      cvc: data.cvc || '',
      month: data.expiryMonth || '',
      year: data.expiryYear || '',
      holderName: data.holderName || ''
    }

    if (this._opts.enableValidations) {
      const errors = this.validate(validations)
      if (errors.length) { return { valid: false, errors } }
    }

    const rsa = this.createRSAKey()
    const aes = new AES()
    const cypher = aes.encrypt(JSON.stringify(data))
    const bytes = sjcl.codec.bytes.fromBits(aes._key)
    const encrypted = rsa.encrypt_b64(bytes)
    const prefix = `adyenjs_${this._encryptVersion}$`

    return { valid: true, value: `${prefix}${encrypted}$${cypher}` }
  }

  /**
   * Create a RSA key with the public key
   *
   * @returns {RSAKey}
   */
  createRSAKey () {
    if (!this._key) { throw new Error('Missing key.') }

    const key = this._key.split('|')
    if (key.length !== 2) { throw new Error('Invalid public key.') }

    const mod = key[1]
    const exp = key[0]

    const rsa = new RSAKey()
    rsa.setPublic(mod, exp)

    return rsa
  }

  /**
   * Check all the fields
   *
   * @param data {Object}
   */
  validate (data) {
    if (typeof data !== 'object') { return false }

    let out = []

    Object.keys(data).forEach(field => {

      let val = data[field]
      let ignore = false

      if (this._opts[`${field}IgnoreNonNumeric`]) { val = val.replace(/D/g, '')}

      Object.keys(data).forEach(relatedField => {
        const possibleOption = this._opts[`${field}IgnoreFor${relatedField}`]
        if (possibleOption && data[relatedField].match(possibleOption)) { ignore = true }
      })

      if (ignore) { return }

      const fieldCheck = {
        number: ::this._checkNumber,
        cvc: ::this._checkCvc,
        expiryYear: ::this._checkYear,
        year: ::this._checkYear,
        expiryMonth: ::this._checkMonth,
        month: ::this._checkMonth,
        holderName: ::this._checkName
      }

      if (fieldCheck[field] && !fieldCheck[field](val)) {
        out.push(field)
      }

    })

    return out
  }

  /**
   * Luhn check for the card number
   *
   * @param val {String}
   */
  _checkLuhn (val) {
    if (isNaN(parseInt(val, 10))) { return false }

    const length = val.length
    const oddEven = length & 1
    let sum = 0
    let cache = {}

    if (typeof cache[val] === 'undefined') {

      for (let cpt = 0; cpt < length; ++cpt) {
        let digit = parseInt(val.charAt(cpt), 10)
        if (!((cpt & 1) ^ oddEven)) {
          digit *= 2
          if (digit > 9) { digit -=9 }
        }
        sum += digit
      }

      cache[val] = (sum % 10 === 0)
    }

    return cache[val]
  }

  /**
   * Check the card number, replace spaces
   *
   * @param val {String}
   */
  _checkNumber (val = '') {
    return (val.replace(/[^\d]/g, '').match(/^\d{10,20}$/) && this._checkLuhn(val))
  }

  /**
   * Check the cvc code
   *
   * @param val {String}
   */
  _checkCvc (val) {
    return (val && val.match && val.match(/^\d{3,4}$/))
  }

  /**
   * Check the year value
   *
   * @param val {String}
   */
  _checkYear (val) {
    return (val && val.match && val.match(/^\d{4}$/))
  }

  /**
   * Check the month value
   *
   * @param val {String}
   */
  _checkMonth (val = '') {
    const month = val.replace(/^0(\d)$/, '$1')
    const monthNum = parseInt(month, 10)
    return (month.match(/^([1-9]|10|11|12)$/) && monthNum >= 1 && monthNum <= 12)
  }

  /**
   * Check if the holder name is composed only by alpha characters
   *
   * @param val {String}
   */
  _checkName (val) {
    return (val && val.match && val.match(/\S/))
  }

}
