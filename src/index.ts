import {
  CreateDidProps,
  CredentialsManager,
  DidCreationResult,
  DidSigner,
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
import * as didJWT from "did-jwt";
import { Resolver } from "did-resolver";

export class DidKeyAdapter implements NetworkAdapter {
  store: StorageSpec<any, any>;
  resolver: Resolver;
  private constructor() {}

  private async buildIdentityAccount(
    props: IdentityAccountProps<StorageSpec<any, any>>
  ): Promise<IdentityAccount> {
    const { seed, store } = props;

    const keyPair = nacl.box.keyPair.fromSecretKey(stringToBytes(seed));
    const provider = new Ed25519Provider(stringToBytes(seed));

    const account = new IdentityAccount();
    const didAccount = new DID({
      provider,
      resolver: this.resolver,
    });
    await didAccount.authenticate();
    const document = (await didAccount.resolve(didAccount.id)).didDocument;

    account.document = document;

    const key =
      bytesToString(keyPair.secretKey) + bytesToString(keyPair.publicKey);
    const keyUint8Array = stringToBytes(key);

    const signer = didJWT.EdDSASigner(keyUint8Array);

    const didSigner: DidSigner = {
      did: account.document.id,
      kid: `${account.document.id}#${
        account.document.id.split(":")[2]
      }` as `did:${string}`,
      signer,
      alg: "EdDSA",
    };
    const credentials = await CredentialsManager.build(
      store,
      didSigner,
      this.resolver
    );
    account.credentials = credentials;
    account.signer = didSigner;

    return account;
  }

  /**
   * Create a new instance of network adapter
   *
   * @param {NetworkAdapterOptions} options
   * @returns {Promise<DidKeyAdapter>}
   */

  public static async build(
    options: NetworkAdapterOptions
  ): Promise<DidKeyAdapter> {
    const adapter = new DidKeyAdapter();
    adapter.store = options.driver;
    adapter.resolver = options.resolver;
    return adapter;
  }

  getMethodIdentifier() {
    return "key";
  }

  /**
   * Create a new DID and store in the store defined with the adapter
   *
   * @param {CreateDidProps} props
   * @returns {Promise<DidCreationResult>}
   */
  async createDid(props: CreateDidProps): Promise<DidCreationResult> {
    const { seed, alias, store } = props;

    const generatedKeyPair = nacl.box.keyPair();
    const generatedSeed = bytesToString(generatedKeyPair.secretKey);

    const identity = await this.buildIdentityAccount({
      seed: seed ?? generatedSeed,
      isOld: !!seed,
      alias,
      store,
    });

    return { identity, seed: seed ?? generatedSeed };
  }

  /**
   * Deserialize a DID and return the DID config result
   *
   * @param {IdentityConfig} config
   * @param {T} store
   * @returns {Promise<DidCreationResult>}
   */
  async deserializeDid<T extends StorageSpec<Record<string, any>, any>>(
    config: IdentityConfig,
    store: T
  ): Promise<DidCreationResult> {
    const identity = await this.buildIdentityAccount({
      seed: config.seed as string,
      isOld: true,
      alias: config.alias,
      store: store,
    });
    return { identity, seed: config.seed as string };
  }
}
