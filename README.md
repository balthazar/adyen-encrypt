# adyen-encrypt

> **[DEPRECATED]** This module is deprecated since the original Adyen CSE project is deprecated and this encrytion method will not work with latest versions of Adyen SDK. Please use the official [Adyen Web Components](https://github.com/Adyen/adyen-web) for Credit Card integration.

> A rewrite of [Adyen-CSE](https://github.com/Adyen/CSE-JS) in ES2015 for the browser

    npm i -S adyen-encrypt

###### Constructor

`key` The public key string you can find in the Adyen customer area

`opts` An object containing optionals as described below

```js
import AdyenEncrypt from 'adyen-encrypt'

const instance = new AdyenEncrypt(key, {
  enableValidations: true,
  numberIgnoreNonNumeric: true,  
  cvcIgnoreBins: '101,404'
})
```

###### encrypt

`data` The object to encrypt

Returns the encrypted string

```js
instance.encrypt({
  number: '5555 4444 3333 1111',
  cvc: '737',
  expiryMonth: '06',
  expiryYear: '2016',
  holderName: 'Balthazar Gronon'
})
```
