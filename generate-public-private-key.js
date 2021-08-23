function base64urlJose(input, url = true) {
  let unencoded = input
  if (typeof unencoded === 'string') {
    unencoded = encoder.encode(unencoded)
  }
  const CHUNK_SIZE = 0x8000
  const arr = []
  for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
    // @ts-expect-error
    arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)))
  }
  const base64string = globalThis.btoa(arr.join(''))

  return base64string.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

/*
Convert a string into an ArrayBuffer
from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String
*/
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function importPublicKeyFormat(key) {
	str2ab(window.atob(key))
}

crypto.subtle.generateKey(
  {
    "name": "ECDSA",
    "namedCurve": "P-256"
  },
  true,
  ["sign", "verify"]
).then(async keys => {
	const exported_key_raw = await crypto.subtle.exportKey("raw", keys.publicKey).then(exported_key => {
  	const asString = ab2str(exported_key)
    const exportedAsBase64 = window.btoa(asString);

    const exportedAsBase64Url = base64urlJose(exported_key);
    console.log('exportedAsBase64', exportedAsBase64);
    console.log('exportedAsBase64Url', exportedAsBase64Url);
    return exported_key
  }).catch((err) => {
    console.log(err);
  });
  
  const cryp = await crypto.subtle.importKey(
  	'raw',
    exported_key_raw,
    {"name": "ECDSA","namedCurve": "P-256"},
    true,
    ["verify"]
  )

	return crypto.subtle.exportKey("pkcs8", keys.privateKey).then(exported_key => {
  	const asString = ab2str(exported_key)
    const bin = (new Uint8Array(exported_key).reduce((acc, curr) => { acc += curr.toString(2); return acc }, '') )
    const exportedAsBase64 = window.btoa(asString);
    console.log(`-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`)
  }).catch((err) => {
    console.log(err);
  });
})

const pemEncodedKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeLhw8zvMj/QIs6W4nfDiS+cGLmhzH3lI0m0UfN4hPfWhRANCAAQE1YL2GZcoxjZmwqNSlPu12OmkVF6WpbvfH98vRgCFDPh/SdUCQrg0n+goh0IvYkYWJMuHly/XIzmWKpViuSap
-----END PRIVATE KEY-----`;

const pemPublicKey = `-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8wjbXilaGYJNPVBH4Bj8j+/w/+BP1daG/XsHmbg5z+eVtn1CbwArDJjwtpCrUiEtmJM3ah7fj/7TefUV6/1e0A==-----END PUBLIC KEY-----`

/*
Import a PEM encoded RSA private key, to use for RSA-PSS signing.
Takes a string containing the PEM encoded key, and returns a Promise
that will resolve to a CryptoKey representing the private key.
*/
async function importPrivateKey(pem) {
  // fetch the part of the PEM string between header and footer
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length)

  // base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  // convert from a binary string to an ArrayBuffer
  const binaryDer = str2ab(binaryDerString);

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "ECDSA",
      namedCurve: 'P-256'
    },
    true,
    ["sign"]
  );
}

(async () => {
  /* console.log('b', await importPrivateKey(pemEncodedKey)) */;
})()
