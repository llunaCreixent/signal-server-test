import axios from 'axios';
import { SIGNAL_SERVER } from './constants';
import { KEMKeyPair, KyberPreKeyRecord, IdentityKeyPair, PrivateKey, SignedPreKeyRecord } from '@signalapp/libsignal-client';

interface KeyGenerationResult {
    registrationId: number;
    pniRegistrationId: number;
    aciIdentityKey: {
        publicKey: string;  // base64
        privateKey: string; // base64
    };
    pniIdentityKey: {
        publicKey: string;  // base64
        privateKey: string; // base64
    };
    aciSignedPreKey: {
        keyId: number;
        publicKey: string;  // base64
        signature: string;  // base64
    };
    pniSignedPreKey: {
        keyId: number;
        publicKey: string;  // base64
        signature: string;  // base64
    };
    aciPqLastResortPreKey: {
        keyId: number;
        publicKey: string;  // base64
        signature: string;  // base64
    };
    pniPqLastResortPreKey: {
        keyId: number;
        publicKey: string;  // base64
        signature: string;  // base64
    };
}

function generatePreKeyId() {
    return Math.floor(Math.random() * 16777215) + 1;
}

async function generateKeys(): Promise<KeyGenerationResult> {
    console.log('🔑 Generating key pairs...');

    // Generate registration IDs (16-bit numbers)
    const registrationId = Math.floor(Math.random() * 16380) + 1;
    const pniRegistrationId = Math.floor(Math.random() * 16380) + 1;

    // Generate identity keys
    const aciIdentityKeyPair = IdentityKeyPair.generate();
    const pniIdentityKeyPair = IdentityKeyPair.generate();

    // Generate signed pre-keys
    const aciSignedPreKeyId = generatePreKeyId();
    const aciSignedPreKey = SignedPreKeyRecord.new(
        aciSignedPreKeyId,
        Math.floor(Date.now() / 1000),
        aciIdentityKeyPair.publicKey,
        aciIdentityKeyPair.privateKey,
        aciIdentityKeyPair.privateKey.sign(aciIdentityKeyPair.publicKey.serialize())
    );

    const pniSignedPreKeyId = generatePreKeyId();
    const pniSignedPreKey = SignedPreKeyRecord.new(
        pniSignedPreKeyId,
        Math.floor(Date.now() / 1000),
        pniIdentityKeyPair.publicKey,
        pniIdentityKeyPair.privateKey,
        pniIdentityKeyPair.privateKey.sign(pniIdentityKeyPair.publicKey.serialize())
    );

    // Generate Kyber pre-keys
    const aciKyberPreKeyId = generatePreKeyId();
    const aciKyberKeyPair = KEMKeyPair.generate();
    const aciKyberPreKey = KyberPreKeyRecord.new(
        aciKyberPreKeyId,
        Math.floor(Date.now() / 1000),
        aciKyberKeyPair,
        aciIdentityKeyPair.privateKey.sign(aciKyberKeyPair.getPublicKey().serialize())
    );

    const pniKyberPreKeyId = generatePreKeyId();
    const pniKyberKeyPair = KEMKeyPair.generate();
    const pniKyberPreKey = KyberPreKeyRecord.new(
        pniKyberPreKeyId,
        Math.floor(Date.now() / 1000),
        pniKyberKeyPair,
        pniIdentityKeyPair.privateKey.sign(pniKyberKeyPair.getPublicKey().serialize())
    );

    // Serialize keys
    const result = {
        registrationId,
        pniRegistrationId,
        aciIdentityKey: {
            publicKey: aciIdentityKeyPair.publicKey.serialize().toString('base64'),
            privateKey: aciIdentityKeyPair.privateKey.serialize().toString('base64')
        },
        pniIdentityKey: {
            publicKey: pniIdentityKeyPair.publicKey.serialize().toString('base64'),
            privateKey: pniIdentityKeyPair.privateKey.serialize().toString('base64')
        },
        aciSignedPreKey: {
            keyId: aciSignedPreKey.id(),
            publicKey: aciSignedPreKey.publicKey().serialize().toString('base64'),
            signature: Buffer.from(aciSignedPreKey.signature()).toString('base64')
        },
        pniSignedPreKey: {
            keyId: pniSignedPreKey.id(),
            publicKey: pniSignedPreKey.publicKey().serialize().toString('base64'),
            signature: Buffer.from(pniSignedPreKey.signature()).toString('base64')
        },
        aciPqLastResortPreKey: {
            keyId: aciKyberPreKey.id(),
            publicKey: aciKyberPreKey.publicKey().serialize().toString('base64'),
            signature: Buffer.from(aciKyberPreKey.signature()).toString('base64')
        },
        pniPqLastResortPreKey: {
            keyId: pniKyberPreKey.id(),
            publicKey: pniKyberPreKey.publicKey().serialize().toString('base64'),
            signature: Buffer.from(pniKyberPreKey.signature()).toString('base64')
        }
    };

    // Validate all keys before returning
    if (!result.aciSignedPreKey.publicKey || !result.pniSignedPreKey.publicKey ||
        !result.aciPqLastResortPreKey.publicKey || !result.pniPqLastResortPreKey.publicKey) {
        throw new Error('Key generation failed: missing required keys');
    }

    return result;
}

async function buildRegistrationRequest(
    sessionId: string,
    recoveryPassword: string | null,
    fcmToken: string | null,
    phoneNumber: string
) {
    const keys = await generateKeys();

    // Create the complete request object
    const request = {
        sessionId,
        number: phoneNumber,
        password: recoveryPassword,
        deviceId: 1,
        accountAttributes: {
            fetchesMessages: true,
            registrationId: keys.registrationId,
            pniRegistrationId: keys.pniRegistrationId,
            name: null,
            capabilities: {
                pni: true,
                paymentActivation: false
            },
            fcmRegistrationId: fcmToken || "fcm-token-test"
        },
        aciIdentityKey: keys.aciIdentityKey.publicKey,
        pniIdentityKey: keys.pniIdentityKey.publicKey,
        deviceActivationRequest: {
            aciSignedPreKey: keys.aciSignedPreKey,
            pniSignedPreKey: keys.pniSignedPreKey,
            aciPqLastResortPreKey: keys.aciPqLastResortPreKey,
            pniPqLastResortPreKey: keys.pniPqLastResortPreKey
        }
    };

    // Validate the request structure
    console.log('Request object:', JSON.stringify(request, null, 2));

    return request;
}

export async function registerUser(phoneNumber: string, password: string, sessionId: string, fcmToken: string) {
    try {
        const request = await buildRegistrationRequest(sessionId, password, fcmToken, phoneNumber);

        const registrationResponse = await axios.post(
            `${SIGNAL_SERVER}/v1/registration`,
            request,
            {
                headers: {
                    'Authorization': `Basic ${Buffer.from(`${phoneNumber}:${password}`).toString('base64')}`,
                    'Content-Type': 'application/json',
                }
            }
        );

        return registrationResponse.data;
    } catch (error: any) {
        console.error('❌ Registration failed:', error.message);
        if (error.response) {
            console.error('   📡 Status:', error.response.status);
            console.error('   💾 Response Data:', JSON.stringify(error.response.data, null, 2));
            console.error('   📝 Headers:', JSON.stringify(error.response.headers, null, 2));
        }
        throw error;
    }
}
