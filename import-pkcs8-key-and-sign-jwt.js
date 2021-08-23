// Utility function for UTF-8 encoding a string to an ArrayBuffer.
const encoder = new TextEncoder('utf-8');

function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0)
  const buf = new Uint8Array(size)
  let i = 0
  buffers.forEach((buffer) => {
    buf.set(buffer, i)
    i += buffer.length
  })
  return buf
}

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

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

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

const pushPayload = {
  aud: "https://fcm.googleapis.com",
  exp: Math.floor(Date.now() / 1000) + (12 * 60 * 60),
  sub: "mailto:valterinside@gmail.com"
}

const jwt_header_fields = { "typ": "JWT", "alg": "ES256" }

const payloadEnc = encoder.encode(base64urlJose(JSON.stringify(pushPayload)))
const protectedHeaderEnc = encoder.encode(base64urlJose(JSON.stringify(jwt_header_fields)))

const data = concat(protectedHeaderEnc, encoder.encode('.'), payloadEnc)
 
// Sign the |unsignedToken| using ES256 (SHA-256 over ECDSA).
const generatedPem = ``;

const main = async function () {
  // Sign the |unsignedToken| with the server's private key to generate
  // the signature.
  //const cKey = await crypto.subtle.importKey('raw', str2ab(generatedPem)), {
  //  name: 'ECDSA', namedCurve: 'P-256',
  //}, true, ['sign'])
  
  const privateKey = await importPrivateKey(generatedPem);

  const signature = await crypto.subtle.sign({
    hash: { name: 'SHA-256' },
    name: 'ECDSA',
    namedCurve: 'P-256'
  }, privateKey, data);

  const base64String = base64urlJose(new Uint8Array(signature));

  const header = base64urlJose(JSON.stringify(jwt_header_fields))
  const payload = base64urlJose(JSON.stringify(pushPayload))

  const jwtSign = header + '.' + payload + '.' + base64String
  console.log(jwtSign)
}

main()
