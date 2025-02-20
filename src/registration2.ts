import { 
    IdentityKeyPair,
    SignedPreKeyRecord,
    KyberPreKeyRecord,
    PrivateKey,
    PublicKey,
    KEMKeyPair,
} from '@signalapp/libsignal-client';

interface PreKeyCollection {
    identityKey: PublicKey;
    signedPreKey: SignedPreKeyRecord;
    lastResortKyberPreKey: KyberPreKeyRecord;
}

interface RegistrationKeys {
    aciPreKeys: PreKeyCollection;
    pniPreKeys: PreKeyCollection;
    registrationId: number;
    pniRegistrationId: number;
}

async function generatePreKeyCollection(identityKeyPair: IdentityKeyPair): Promise<PreKeyCollection> {
    const signedPreKeyId = Math.floor(Math.random() * 16777215); // Similar to Medium.MAX_VALUE in Java
    const kyberPreKeyId = Math.floor(Math.random() * 16777215);

    // Generate signed prekey
    const signedPreKey = generateSignedPreKey(
        signedPreKeyId,
        identityKeyPair.privateKey
    );

    // Generate last resort kyber prekey
    const lastResortKyberPreKey = generateLastResortKyberPreKey(
        kyberPreKeyId,
        identityKeyPair.privateKey
    );

    return {
        identityKey: identityKeyPair.publicKey,
        signedPreKey,
        lastResortKyberPreKey
    };
}

function generateSignedPreKey(
    id: number,
    identityPrivateKey: PrivateKey
): SignedPreKeyRecord {
    const keyPair = PrivateKey.generate();
    const signature = identityPrivateKey.sign(keyPair.getPublicKey().serialize());
    
    return SignedPreKeyRecord.new(
        id,
        Math.floor(Date.now() / 1000),
        keyPair.getPublicKey(),
        keyPair,
        signature
    );
}

function generateLastResortKyberPreKey(
    id: number,
    identityPrivateKey: PrivateKey
): KyberPreKeyRecord {
    const keyPair = KEMKeyPair.generate();
    const signature = identityPrivateKey.sign(keyPair.getPublicKey().serialize());

    return KyberPreKeyRecord.new(
        id,
        Math.floor(Date.now() / 1000),
        keyPair,
        signature
    );
}

async function generateRegistrationKeys(): Promise<RegistrationKeys> {
    // Generate ACI (Account Identity) keys
    const aciIdentityKeyPair: IdentityKeyPair = IdentityKeyPair.generate();
    
    // Generate PNI (Phone Number Identity) keys
    const pniIdentityKeyPair: IdentityKeyPair = IdentityKeyPair.generate();
    
    // Generate registration IDs
    const registrationId = Math.floor(Math.random() * 16380) + 1;
    const pniRegistrationId = Math.floor(Math.random() * 16380) + 1;

    // Generate ACI PreKey collection
    const aciPreKeys = await generatePreKeyCollection(aciIdentityKeyPair);

    // Generate PNI PreKey collection
    const pniPreKeys = await generatePreKeyCollection(pniIdentityKeyPair);

    return {
        aciPreKeys,
        pniPreKeys,
        registrationId,
        pniRegistrationId
    };
}
