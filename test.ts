import { Session } from '@0xsequence/auth'
import { isValidMessageSignature } from '@0xsequence/provider'
import { context } from '@0xsequence/tests'
import * as chai from 'chai'
import { expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import 'dotenv/config'
import { ethers } from 'ethers'
import { it } from 'mocha'

import { GoogleKmsSigner } from '.'

const { PROJECT, LOCATION, KEY_RING, CRYPTO_KEY, CRYPTO_KEY_VERSION } = process.env
if (!PROJECT || !LOCATION || !KEY_RING || !CRYPTO_KEY || !CRYPTO_KEY_VERSION) {
  throw new Error('missing values in .env file')
}

const signer = new GoogleKmsSigner({
  project: PROJECT,
  location: LOCATION,
  keyRing: KEY_RING,
  cryptoKey: CRYPTO_KEY,
  cryptoKeyVersion: CRYPTO_KEY_VERSION
})

chai.use(chaiAsPromised)

it('should sign a message', async function () {
  this.timeout(30000)

  const message = 'hello world'
  const signature = await signer.signMessage(message)
  const address = ethers.utils.verifyMessage(message, signature)

  expect(address).to.equal(await signer.getAddress())
})

it('should sign a transaction', async function () {
  const provider = new ethers.providers.JsonRpcProvider('http://127.0.0.1:8545')

  let balance = await provider.getBalance(signer.getAddress())
  if (balance.lt(1000000000)) {
    const faucet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80').connect(provider)
    await (await faucet.sendTransaction({ to: await signer.getAddress(), value: '1000000000000000000' })).wait()
    balance = await provider.getBalance(signer.getAddress())
  }

  const receipt = await (
    await signer.connect(provider).sendTransaction({ to: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', value: 1 })
  ).wait()

  expect(receipt.status).to.equal(1)
  expect(receipt.from).to.equal(await signer.getAddress())
  expect((await provider.getBalance(await signer.getAddress())).lt(balance)).to.be.true
})

it('should sign for a sequence wallet', async function () {
  this.timeout(30000)

  const provider = new ethers.providers.JsonRpcProvider('http://127.0.0.1:8545')
  const { chainId } = await provider.getNetwork()

  const faucet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80').connect(provider)
  await context.deploySequenceContexts(faucet)

  const session = await Session.singleSigner({ signer, projectAccessKey: '' })

  const message = ethers.utils.toUtf8Bytes('hello world')
  const signature = await session.account.signMessage(message, chainId, 'eip6492')

  expect(isValidMessageSignature(session.account.address, message, signature, provider)).to.eventually.be.true
})
