import type { Deferrable } from '@ethersproject/properties'
import { type UnsignedTransaction, serialize } from '@ethersproject/transactions'
import { KeyManagementServiceClient } from '@google-cloud/kms'
import { ECDSASigValue } from '@peculiar/asn1-ecc'
import { AsnConvert } from '@peculiar/asn1-schema'
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509'
import { ethers, getBytes, toBigInt, N as secp256k1N, recoverAddress as recoverAddressFn, toBeHex, Signature } from 'ethers'

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
        value: Record<string, unknown>
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

    private async getPubkey(): Promise<string> {
        if (!this.pubkey) {
            const [pubkey] = await this.client().getPublicKey({ name: this.identifier })
            if (pubkey.algorithm !== 'EC_SIGN_SECP256K1_SHA256') {
                throw new Error(`algorithm is ${pubkey.algorithm}, expected EC_SIGN_SECP256K1_SHA256`)
            }
            if (!pubkey.pem) {
                throw new Error('missing public key pem')
            }

            const PREFIX = '-----BEGIN PUBLIC KEY-----'
            const SUFFIX = '-----END PUBLIC KEY-----'

            const pemContent = pubkey.pem
                .replace(PREFIX, '')
                .replace(SUFFIX, '')
                .replace(/\s/g, '')

            const derBuffer = Buffer.from(pemContent, 'base64')

            const publicKeyInfo = AsnConvert.parse(derBuffer, SubjectPublicKeyInfo)

            const publicKeyBytes = new Uint8Array(publicKeyInfo.subjectPublicKey)

            const keyBytes = publicKeyBytes[0] === 0x04 ? publicKeyBytes.slice(1) : publicKeyBytes

            return `0x${Buffer.from(keyBytes).toString('hex')}`
        }

        return this.pubkey
    }

    private async signDigest(digest: ethers.BytesLike): Promise<string> {
        const digestData = getBytes(digest)

        const [signature] = await this.client().asymmetricSign({ name: this.identifier, digest: { sha256: digestData } })
        if (!(signature.signature instanceof Uint8Array)) {
            throw new Error(`signature is ${typeof signature.signature}, expected Uint8Array`)
        }

        const parsedSignature = AsnConvert.parse(
            Buffer.from(signature.signature),
            ECDSASigValue,
        );

        let s = toBigInt(new Uint8Array(parsedSignature.s));
        s = s > secp256k1N / BigInt(2) ? secp256k1N - s : s;

        const recoverAddress = recoverAddressFn(digest, {
            r: toBeHex(toBigInt(new Uint8Array(parsedSignature.r)), 32),
            s: toBeHex(s, 32),
            v: 0x1b,
        });

        const address = await this.getAddress();

        return Signature.from({
            r: toBeHex(toBigInt(new Uint8Array(parsedSignature.r)), 32),
            s: toBeHex(s, 32),
            v: recoverAddress.toLowerCase() !== address.toLowerCase() ? 0x1c : 0x1b,
        }).serialized;
    }
}
