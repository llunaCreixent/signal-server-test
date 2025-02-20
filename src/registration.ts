import axios from 'axios';
import { SIGNAL_SERVER } from './constants';
import { KEMKeyPair, KyberPreKeyRecord, PrivateKey, SignedPreKeyRecord } from '@signalapp/libsignal-client';
import { IdentityKeyPair } from '@signalapp/libsignal-client';



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
        id: number;
        publicKey: string;  // base64
        signature: string;  // base64
    };
    pniSignedPreKey: {
        id: number;
        publicKey: string;  // base64
        signature: string;  // base64
    };
    aciPqLastResortPreKey: {
        id: number;
        publicKey: string;  // base64
        signature: string;  // base64
    };
    pniPqLastResortPreKey: {
        id: number;
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

    // Generate identity keys using proper libsignal methods
    const aciIdentityKeyPair = IdentityKeyPair.generate();
    const pniIdentityKeyPair = IdentityKeyPair.generate();

    // Generate signed pre-keys with proper serialization
    const aciSignedPreKeyId = generatePreKeyId();
    const aciKeyPair = PrivateKey.generate();
    const aciSignedPreKey = SignedPreKeyRecord.new(
        aciSignedPreKeyId,
        Math.floor(Date.now() / 1000),
        aciKeyPair.getPublicKey(),
        aciKeyPair,
        aciIdentityKeyPair.privateKey.sign(aciKeyPair.getPublicKey().serialize())
    );

    const pniSignedPreKeyId = generatePreKeyId();
    const pniKeyPair = PrivateKey.generate();
    const pniSignedPreKey = SignedPreKeyRecord.new(
        pniSignedPreKeyId,
        Math.floor(Date.now() / 1000),
        pniKeyPair.getPublicKey(),
        pniKeyPair,
        pniIdentityKeyPair.privateKey.sign(pniKeyPair.getPublicKey().serialize())
    );

    // Generate Kyber pre-keys with proper serialization
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

    // Properly serialize all keys using libsignal methods
    const result = {
        registrationId,
        pniRegistrationId,
        aciIdentityKey: {
            // Use proper serialization for identity keys
            publicKey: aciIdentityKeyPair.publicKey.serialize().toString('base64'),
            privateKey: aciIdentityKeyPair.privateKey.serialize().toString('base64')
        },
        pniIdentityKey: {
            publicKey: pniIdentityKeyPair.publicKey.serialize().toString('base64'),
            privateKey: pniIdentityKeyPair.privateKey.serialize().toString('base64')
        },
        aciSignedPreKey: {
            id: aciSignedPreKey.id(),
            // Use proper serialization for signed pre-keys
            publicKey: aciSignedPreKey.publicKey().serialize().toString('base64'),
            signature: Buffer.from(aciSignedPreKey.signature()).toString('base64')
        },
        pniSignedPreKey: {
            id: pniSignedPreKey.id(),
            publicKey: pniSignedPreKey.publicKey().serialize().toString('base64'),
            signature: Buffer.from(pniSignedPreKey.signature()).toString('base64')
        },
        aciPqLastResortPreKey: {
            id: aciKyberPreKey.id(),
            // Use proper serialization for Kyber pre-keys
            publicKey: aciKyberPreKey.publicKey().serialize().toString('base64'),
            signature: Buffer.from(aciKyberPreKey.signature()).toString('base64')
        },
        pniPqLastResortPreKey: {
            id: pniKyberPreKey.id(),
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

    // First create the device activation request exactly as Signal-Android does
    const deviceActivationRequest = {
        // Note: These must be direct properties, not nested objects
        aciSignedPreKeyId: keys.aciSignedPreKey.id,
        aciSignedPreKeyPublic: keys.aciSignedPreKey.publicKey,
        aciSignedPreKeySignature: keys.aciSignedPreKey.signature,

        pniSignedPreKeyId: keys.pniSignedPreKey.id,
        pniSignedPreKeyPublic: keys.pniSignedPreKey.publicKey,
        pniSignedPreKeySignature: keys.pniSignedPreKey.signature,

        aciPqLastResortPreKeyId: keys.aciPqLastResortPreKey.id,
        aciPqLastResortPreKeyPublic: keys.aciPqLastResortPreKey.publicKey,
        aciPqLastResortPreKeySignature: keys.aciPqLastResortPreKey.signature,

        pniPqLastResortPreKeyId: keys.pniPqLastResortPreKey.id,
        pniPqLastResortPreKeyPublic: keys.pniPqLastResortPreKey.publicKey,
        pniPqLastResortPreKeySignature: keys.pniPqLastResortPreKey.signature
    };

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
        deviceActivationRequest
    };

    // Validate the request structure
    console.log('Device Activation Request:', JSON.stringify(deviceActivationRequest, null, 2));

    const headers = {
        'Authorization': `Basic ${Buffer.from(`${request.number}:${request.password}`).toString('base64')}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Signal-Android/6.34.0'
    };

    return { request, headers };
}

export async function registerUser(phoneNumber: string, password: string, sessionId: string, fcmToken: string) {
    try {
        const { request, headers } = await buildRegistrationRequest(sessionId, password, fcmToken, phoneNumber);

        const registrationResponse = await axios.post(
            `${SIGNAL_SERVER}/v1/registration`,
            request,
            { headers }
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
