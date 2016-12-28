# adyen-encrypt

> A rewrite of [Adyen-CSE](https://github.com/Adyen/CSE-JS) in ES2015 for the browser

    npm i -S adyen-encrypt

###### Constructor

`key` The public key string you can find in the Adyen customer area

`opts` An object containing optionals as described below

    import AdyenEncrypt from 'adyen-encrypt'

    const instance = new AdyenEncrypt(key, {
      enableValidations: true,
      numberIgnoreNonNumeric: true,
      cvcIgnoreBins: '101,404'
    })

###### encrypt

`data` The object to encrypt

Returns the encrypted string

    instance.encrypt({
      number: '5555 4444 3333 1111',
      cvc: '737',
      expiryMonth: '06',
      expiryYear: '2016',
      holderName: 'Balthazar Gronon'
    })
