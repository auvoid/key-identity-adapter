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
import * as KeyResolver from "key-did-resolver";

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

    public static async build(props: IdentityAccountProps<any>) {
        const { seed } = props;

        const provider = new Ed25519Provider(stringToBytes(seed));

        const account = new DidKeyAccount();
        const credentials = new DidKeyCredentialsManager();
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
    createPresentation(credentials: string[]): Promise<Record<string, any>> {
        throw new Error("Method not implemented.");
    }
}

export class DidKeyCredentialsManager<
    T extends StorageSpec<Record<string, any>, any>
> implements CredentialsManager<T>
{
    store: T;
    isCredentialValid(credential: Record<string, unknown>): Promise<boolean> {
        throw new Error("Method not implemented.");
    }
    verify(credential: Record<string, unknown>): Promise<IVerificationResult> {
        throw new Error("Method not implemented.");
    }
    create(options: CreateCredentialProps): Promise<Record<string, any>> {
        throw new Error("Method not implemented.");
    }
    revoke(keyIndex: number): Promise<void> {
        throw new Error("Method not implemented.");
    }
}
