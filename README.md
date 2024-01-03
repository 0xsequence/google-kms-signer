# google-kms-signer

[GoogleKmsSigner](https://github.com/0xsequence/google-kms-signer) is an [ethers.js](https://ethers.org)- and [sequence.js](https://github.com/0xsequence/sequence.js)-compatible signer using [Google Cloud Key Management Service](https://cloud.google.com/security/products/security-key-management) keys

## prerequisites

### create google cloud kms key

https://console.cloud.google.com/security/kms/keyrings

1. create project or use existing one
2. create key ring or use existing one
3. create key
  - protection level: hsm
  - key material: hsm-generated
  - purpose: asymmetric sign
  - algorithm: elliptic curve secp256k1 - sha256 digest

### set up application default credentials

https://cloud.google.com/kms/docs/reference/libraries#authentication

1. install [gcloud cli](https://cloud.google.com/sdk/docs/install)
2. `gcloud auth application-default login`
3. authenticate

## installation

these instructions assume [pnpm](https://pnpm.io), please refer to docs if you use something else

```sh
pnpm add @0xsequence/google-kms-signer
```

## usage

### integration

create a signer:

```ts
import { GoogleKmsSigner } from '@0xsequence/google-kms-signer'

const signer = new GoogleKmsSigner({
  project: 'my-project',
  location: 'my-location',
  keyRing: 'my-key-ring',
  cryptoKey: 'my-crypto-key',
  cryptoKeyVersion: 'my-crypto-key-version'
})
```

get your signer's address:

```ts
const address = await signer.getAddress()
console.log(address)
```

sign a message:

```ts
const message = 'hello world'
const signature = await signer.signMessage(message)

console.log(signature)
console.log(`${ethers.utils.verifyMessage(message, signature)} = ${address}`)
```

send a transaction:

```ts
const provider = new ethers.providers.JsonRpcProvider('https://my-json-rpc-provider.com')
const connectedSigner = signer.connect(provider)

const response = await connectedSigner.sendTransaction({
  to: 'destination address',
  value: 123
})

const receipt = await response.wait()
console.log(receipt)
```

sign for a sequence wallet:

```ts
import { Session } from '@0xsequence/auth'
import { isValidMessageSignature } from '@0xsequence/provider'

const session = await Session.singleSigner({
  signer,
  projectAccessKey: 'my-project-access-key'
})

const message = ethers.utils.toUtf8Bytes('hello world')
const signature = await session.account.signMessage(message, chainId, 'eip6492')

console.log(isValidMessageSignature(session.account.address, message, signature, provider))
```

### running tests

```sh
cp .env.sample .env
```

edit the .env file, then:

```sh
pnpm test
```
