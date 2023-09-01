import {
    CreateCredentialProps,
    CreateDidProps,
    CredentialsManager,
    DidCreationResult,
    IVerificationResult,
    IdentityAccount,
    IdentityAccountProps,
    IdentityConfig,
    NetworkAdapter,
    NetworkAdapterOptions,
    StorageSpec,
    bytesToString,
    stringToBytes,
} from "@tanglelabs/ssimon";
import nacl from "tweetnacl";
import { DID } from "dids";
import { Ed25519Provider } from "key-did-provider-ed25519";
import {
    JwtCredentialPayload,
    createVerifiableCredentialJwt,
    JwtPresentationPayload,
    createVerifiablePresentationJwt,
    verifyCredential,
} from "did-jwt-vc";
import * as didJWT from "did-jwt";
import * as KeyResolver from "key-did-resolver";
import { Resolver } from "did-resolver";

export class DidKeyAdapter implements NetworkAdapter {
    store: StorageSpec<any, any>;
    private constructor() {}

    public static async build(options: NetworkAdapterOptions) {
        const adapter = new DidKeyAdapter();
        adapter.store = options.driver;
        return adapter;
    }

    async createDid<T extends StorageSpec<Record<string, any>, any>>(
        props: CreateDidProps<T>
    ): Promise<DidCreationResult> {
        const { seed, alias, store } = props;

        const generatedKeyPair = nacl.box.keyPair();
        const generatedSeed = bytesToString(generatedKeyPair.secretKey);

        const identity = await DidKeyAccount.build({
            seed: seed ?? generatedSeed,
            isOld: !!seed,
            alias,
            store,
        });

        return { identity, seed: seed ?? generatedSeed };
    }

    async deserializeDid<T extends StorageSpec<Record<string, any>, any>>(
        config: IdentityConfig,
        store: T
    ): Promise<DidCreationResult> {
        const identity = await DidKeyAccount.build({
            seed: config.seed as string,
            isOld: true,
            alias: config.alias,
            store: store,
        });
        return { identity, seed: config.seed as string };
    }
}

export class DidKeyAccount implements IdentityAccount {
    credentials: CredentialsManager<StorageSpec<Record<string, any>, any>>;
    account: DID;
    keyPair: nacl.BoxKeyPair;

    public static async build(props: IdentityAccountProps<any>) {
        const { seed, store } = props;

        const keyPair = nacl.box.keyPair.fromSecretKey(stringToBytes(seed));
        const provider = new Ed25519Provider(stringToBytes(seed));

        const account = new DidKeyAccount();
        const credentials = await DidKeyCredentialsManager.build(
            store,
            account
        );
        account.keyPair = keyPair;
        account.account = new DID({
            provider,
            resolver: KeyResolver.getResolver(),
        });
        await account.account.authenticate();

        account.credentials = credentials;

        return account;
    }

    getDid(): string {
        return this.account.id;
    }
    async getDocument(): Promise<Record<string, any>> {
        return this.account.resolve(this.account.id);
    }

    async createPresentation(
        credentials: string[]
    ): Promise<Record<string, any>> {
        const key =
            bytesToString(this.keyPair.secretKey) +
            bytesToString(this.keyPair.publicKey);
        const keyUint8Array = stringToBytes(key);

        const signer = didJWT.EdDSASigner(keyUint8Array);
        const vpIssuer = {
            did: this.getDid(),
            signer,
            alg: "EdDSA",
        };

        const vpPayload: JwtPresentationPayload = {
            vp: {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiablePresentation"],
                verifiableCredential: credentials,
            },
        };

        const presentationJwt = await createVerifiablePresentationJwt(
            vpPayload,
            vpIssuer
        );

        return { vpPayload, presentationJwt };
    }
}

export class DidKeyCredentialsManager<
    T extends StorageSpec<Record<string, any>, any>
> implements CredentialsManager<T>
{
    store: T;
    account: DidKeyAccount;

    private constructor() {}

    public static async build<T extends StorageSpec<Record<string, any>, any>>(
        store: T,
        account: DidKeyAccount
    ) {
        const credentialsManager = new DidKeyCredentialsManager();
        credentialsManager.store = store;
        credentialsManager.account = account;
        return credentialsManager;
    }
    async isCredentialValid(
        credential: Record<string, unknown>
    ): Promise<boolean> {
        const result = await this.verify(credential);
        return result.vc;
    }
    async verify(
        credential: Record<string, unknown>
    ): Promise<IVerificationResult> {
        const { cred } = credential;
        const keyDIDResolver = KeyResolver.getResolver();
        const didResolver = new Resolver(keyDIDResolver);
        await verifyCredential(cred as string, didResolver);
        return { vc: true, dvid: true };
    }

    async create(options: CreateCredentialProps): Promise<Record<string, any>> {
        const { id, recipientDid, body, type } = options;

        const key =
            bytesToString(this.account.keyPair.secretKey) +
            bytesToString(this.account.keyPair.publicKey);
        const keyUint8Array = stringToBytes(key);

        const signer = didJWT.EdDSASigner(keyUint8Array);
        const didId =
            this.account.getDid() +
            "#" +
            this.account.getDid().split("did:key:")[1];
        const vcIssuer = {
            did: didId,
            signer,
            alg: "EdDSA",
        };
        const types = Array.isArray(type) ? [...type] : [type];

        const credential: JwtCredentialPayload = {
            sub: recipientDid,
            nbf: Math.floor(Date.now() / 1000),
            id,
            vc: {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiableCredential", ...types],
                id,
                credentialSubject: {
                    ...body,
                },
            },
        };
        const jwt = await createVerifiableCredentialJwt(credential, vcIssuer);

        return { cred: jwt };
    }
    revoke(keyIndex: number): Promise<void> {
        throw new Error("Method not implemented.");
    }
}
