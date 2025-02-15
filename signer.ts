import { arrayify, joinSignature } from '@ethersproject/bytes'
import { Deferrable } from '@ethersproject/properties'
import { recoverPublicKey } from '@ethersproject/signing-key'
import { UnsignedTransaction, serialize } from '@ethersproject/transactions'
import { KeyManagementServiceClient } from '@google-cloud/kms'
import * as asn1js from 'asn1js'
import { ethers } from 'ethers'
import { PublicKeyInfo } from 'pkijs'

type GoogleKmsKey = {
    project: string
    location: string
    keyRing: string
    cryptoKey: string
    cryptoKeyVersion: string
}

export class GoogleKmsSigner extends ethers.AbstractSigner {
    private address?: Promise<string>
    private pubkey?: Promise<string>

    private readonly client: () => KeyManagementServiceClient
    private readonly identifier: string

    constructor(
        private readonly path: GoogleKmsKey,
        client = new KeyManagementServiceClient(),
        provider?: ethers.Provider,
    ) {
        super(provider)

        this.client = () => client

        this.identifier = this.client().cryptoKeyVersionPath(
            this.path.project,
            this.path.location,
            this.path.keyRing,
            this.path.cryptoKey,
            this.path.cryptoKeyVersion
        )
    }

    getAddress(): Promise<string> {
        if (!this.address) {
            this.address = this.getPubkey().then(ethers.computeAddress)
        }

        return this.address
    }

    signMessage(message: string | ethers.BytesLike): Promise<string> {
        return this.signDigest(ethers.hashMessage(message))
    }

    async signTransaction(tx: Deferrable<ethers.TransactionRequest>): Promise<string> {
        const resolved = await ethers.resolveProperties(tx)
        if (resolved.from !== undefined) {
            const address = await this.getAddress()
            if (resolved.from !== address) {
                throw new Error(`from address is ${resolved.from}, expected ${address}`)
            }
        }
        const signature = await this.signDigest(ethers.keccak256(serialize(tx as UnsignedTransaction)));
        return serialize(tx as UnsignedTransaction, signature);
    }

    async signTypedData(
        domain: ethers.TypedDataDomain,
        types: Record<string, Array<ethers.TypedDataField>>,
        value: Record<string, any>
    ): Promise<string> {
        const resolved = await ethers.TypedDataEncoder.resolveNames(domain, types, value, async name => {
            if (!this.provider) {
                throw new Error(`unable to resolve ens name ${name}: no provider`)
            }

            const resolved = await this.provider.resolveName(name)
            if (!resolved) {
                throw new Error(`unable to resolve ens name ${name}`)
            }

            return resolved
        })

        return this.signDigest(ethers.TypedDataEncoder.hash(resolved.domain, types, resolved.value))
    }

    connect(provider: ethers.Provider): ethers.Signer {
        return new GoogleKmsSigner(this.path, this.client(), provider)
    }

    private getPubkey(): Promise<string> {
        if (!this.pubkey) {
            this.pubkey = (async () => {
                const [pubkey] = await this.client().getPublicKey({ name: this.identifier })
                if (pubkey.algorithm !== 'EC_SIGN_SECP256K1_SHA256') {
                    throw new Error(`algorithm is ${pubkey.algorithm}, expected EC_SIGN_SECP256K1_SHA256`)
                }
                if (!pubkey.pem) {
                    throw new Error('missing public key pem')
                }

                return decodePubkey(pubkey.pem)
            })()
        }

        return this.pubkey
    }

    private async signDigest(digest: ethers.BytesLike): Promise<string> {
        const digestData = arrayify(digest)

        const [signature] = await this.client().asymmetricSign({ name: this.identifier, digest: { sha256: digestData } })
        if (!(signature.signature instanceof Uint8Array)) {
            throw new Error(`signature is ${typeof signature.signature}, expected Uint8Array`)
        }

        return computeSignature(digestData, decodeSignature(signature.signature), await this.getPubkey())
    }
}

function decodePubkey(pem: string): string {
    const PREFIX = '-----BEGIN PUBLIC KEY-----\n'
    const SUFFIX = '-----END PUBLIC KEY-----\n'

    if (!pem.startsWith(PREFIX)) {
        throw new Error('missing public key prefix')
    }
    if (!pem.endsWith(SUFFIX)) {
        throw new Error('missing public key suffix')
    }

    pem = pem.slice(PREFIX.length, pem.length - SUFFIX.length)
    pem = pem.replace(/\s/, '')

    const pubkey = PublicKeyInfo.fromBER(Buffer.from(pem, 'base64'))
    return ethers.hexlify(pubkey.subjectPublicKey.valueBlock.valueHexView)
}

function decodeSignature(ber: Uint8Array): { r: bigint; s: bigint } {
    const SCHEMA = new asn1js.Sequence({ value: [new asn1js.Integer({ name: 'r' }), new asn1js.Integer({ name: 's' })] })

    const { verified, result } = asn1js.verifySchema(ber, SCHEMA)
    if (!verified) {
        throw new Error('signature does not conform to schema')
    }

    return { r: result.r.toBigInt(), s: result.s.toBigInt() }
}

function computeSignature(digest: ethers.BytesLike, signature: { r: bigint; s: bigint }, pubkey: string): string {
    const r = ethers.toBeHex(signature.r)
    const s = ethers.toBeHex(signature.s)

    for (const v of [27, 28]) {

        if (recoverPublicKey(digest, { r, s, v }) === pubkey) {
            const signature = joinSignature({ r, s, v })
            return signature
        }
    }

    throw new Error('invalid signature for public key')
}