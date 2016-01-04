const key = '...'

const instance = new AdyenEncrypt(key, {
  enableValidations: true,
  numberIgnoreNonNumeric: true,
  cvcIgnoreBins: '303,404'
})

const res = instance.encrypt({
  number: '5555 4444 3333 1111',
  cvc: '100',
  expiryMonth: '06',
  expiryYear: '2016',
  holderName: 'Balthazar Gronon'
})
