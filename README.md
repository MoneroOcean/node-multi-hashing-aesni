node-cryptonight-hashing
===============

Cryptonight hashing functions for node.js.


Algorithms
----------
* cryptonight (v0, v1, v2, xtl, msr, rto, xao)
* cryptonight-light (v0, v1)
* cryptonight-heavy (v0, xhv, tube)
* cryptonight-upx

Usage
-----

Install

```bash
npm install https://github.com/MoneroOcean/node-cryptonight-hashing.git
```

So far this native Node.js addon can do the following hashing algos

```javascript
var multiHashing = require('cryptonight-hashing');

var algorithms = ['cryptonight', 'cryptonight_light', 'cryptonight_heavy', 'cryptonight-upx' ];

var data = new Buffer("7000000001e980924e4e1109230383e66d62945ff8e749903bea4336755c00000000000051928aff1b4d72416173a8c3948159a09a73ac3bb556aa6bfbcad1a85da7f4c1d13350531e24031b939b9e2b", "hex");

var hashedData = algorithms.map(function(algo){
    return multiHashing[algo](data);
});


console.log(hashedData);

// [ <Buffer e9 7e f3 fc 03 6d 67 62 6e 54 54 7a 71 30 73 03 dc 5f a8 9b 9d f4 99 fe ea ef 9d 11 ac ad be 9b>,
//   <Buffer f5 01 e0 d0 c7 88 90 bd 07 92 6a a8 a1 26 c4 f2 a6 72 4f f1 82 82 c1 01 61 61 12 e0 29 46 59 b9>,
//   <Buffer f2 28 83 71 4c 99 87 b1 b4 da b7 92 60 e2 d4 96 12 43 28 ba 13 6f 54 68 53 f7 9b 1e d3 58 02 85> ]

```

Credits
-------
* [XMrig](https://github.com/xmrig) - For advanced cryptonight implementations from [XMrig](https://github.com/xmrig/xmrig)
