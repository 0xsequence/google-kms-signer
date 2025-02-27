import { Session } from '@0xsequence/auth'
import { isValidMessageSignature, isValidTypedDataSignature } from '@0xsequence/provider'
import * as chai from 'chai'
import { expect } from 'chai'
import chaiAsPromised from 'chai-as-promised'
import 'dotenv/config'
import { type TransactionResponse, ethers } from 'ethers'
import { it } from 'mocha'

import { GoogleKmsSigner } from '.'

const { PROJECT, LOCATION, KEY_RING, CRYPTO_KEY, CRYPTO_KEY_VERSION, PROJECT_ACCESS_KEY } = process.env
if (!PROJECT || !LOCATION || !KEY_RING || !CRYPTO_KEY || !CRYPTO_KEY_VERSION || !PROJECT_ACCESS_KEY) {
  throw new Error('missing values in .env file')
}

const googleKmsEthersSigner = new GoogleKmsSigner({
  project: PROJECT,
  location: LOCATION,
  keyRing: KEY_RING,
  cryptoKey: CRYPTO_KEY,
  cryptoKeyVersion: CRYPTO_KEY_VERSION
})

chai.use(chaiAsPromised)

it('should sign a message with kms EOA', async function () {
  this.timeout(30000)

  const message = 'hello world'
  const signature = await googleKmsEthersSigner.signMessage(message)
  const address = ethers.verifyMessage(message, signature)

  expect(address).to.equal(await googleKmsEthersSigner.getAddress())
})

it('should send a transaction using the sequence smart account', async function () {
  this.timeout(10000)
  const provider = new ethers.JsonRpcProvider('https://arbitrum-sepolia.drpc.org')
  const { chainId } = await provider.getNetwork()
  const session = await Session.singleSigner({ signer: googleKmsEthersSigner, projectAccessKey: PROJECT_ACCESS_KEY })

  const tx = {
    to: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    value: 1,
    data: '0x'
  }

  const sessionSigner = session.account.getSigner(Number(chainId));
  const smartAccountAddress = await sessionSigner.getAddress()

  let balance = await provider.getBalance(smartAccountAddress)
  if (balance < BigInt(1000000000)) {
    const faucet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80').connect(provider)
    await (await faucet.sendTransaction({ to: smartAccountAddress, value: '1000000000000000000' })).wait()
    balance = await provider.getBalance(smartAccountAddress)
  }

  const response: TransactionResponse | undefined = await sessionSigner.sendTransaction(tx);
  const receipt = await response?.wait();
  expect(receipt?.status).to.equal(1)
})

it('should send a transaction with kms EOA', async function () {
  this.timeout(10000)
  const provider = new ethers.JsonRpcProvider('http://127.0.0.1:8545')

  let balance = await provider.getBalance(googleKmsEthersSigner.getAddress())
  if (balance < BigInt(1000000000)) {
    const faucet = new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80').connect(provider)
    await (await faucet.sendTransaction({ to: await googleKmsEthersSigner.getAddress(), value: '1000000000000000000' })).wait()
    balance = await provider.getBalance(googleKmsEthersSigner.getAddress())
  }

  const connectedSigner = googleKmsEthersSigner.connect(provider)

  const tx = {
    to: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    value: 1,
    chainId: (await provider.getNetwork()).chainId,
  }
  
  const txResponse = await connectedSigner.sendTransaction(tx)
  const receipt = await txResponse.wait()

  expect(receipt?.status).to.equal(1)
  expect(receipt?.from).to.equal(await connectedSigner.getAddress())
  expect((await provider.getBalance(await googleKmsEthersSigner.getAddress())) < balance).to.be.true
})

it('should sign typed data with sequence smart account', async function () {
  this.timeout(10000)
  const provider = new ethers.JsonRpcProvider('https://arbitrum-sepolia.drpc.org')
  const { chainId } = await provider.getNetwork()

  // Create a single signer sequence wallet session
  const session = await Session.singleSigner({
    signer: googleKmsEthersSigner,
    projectAccessKey: 'AQAAAAAAAHqkq694NhWZQdSNJyA6ubOK494'
  })

  const sessionSigner = session.account.getSigner(Number(chainId));
  
  const typedData = {
    domain: {
      name: "Ether Mail",
      version: "1",
      chainId: await sessionSigner.getChainId(),
      verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    },
    types: {
      Person: [
        { name: "name", type: "string" },
        { name: "wallet", type: "address" },
      ],
    },
    message: {
      name: "Bob",
      wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
    },
  };

  const signature = await sessionSigner.signTypedData(
    typedData.domain,
    typedData.types,
    typedData.message
  )

  const isValid = await isValidTypedDataSignature(
    await sessionSigner.getAddress(),
    typedData,
    signature,
    provider
  )

  expect(isValid).to.be.true
})

it('should sign a message with sequence smart account', async function () {
  this.timeout(10000)
  const provider = new ethers.JsonRpcProvider('https://arbitrum-sepolia.drpc.org')
  const { chainId } = await provider.getNetwork()

  const session = await Session.singleSigner({
    signer: googleKmsEthersSigner,
    projectAccessKey: process.env.PROJECT_ACCESS_KEY || ''
  })

  const message = 'Hello world'
  const messageBytes = ethers.toUtf8Bytes(message)
  const eip191prefix = ethers.toUtf8Bytes('\x19Ethereum Signed Message:\n')

  const prefixedMessage = ethers.getBytes(
    ethers.concat([eip191prefix, ethers.toUtf8Bytes(String(messageBytes.length)), messageBytes])
  )

  const signature = await session.account.signMessage(prefixedMessage, chainId, 'eip6492')
  const isValid = await isValidMessageSignature(session.account.address, message, signature, provider)

  expect(isValid).to.be.true
})

