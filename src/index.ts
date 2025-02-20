import axios from 'axios';
import { 
    IdentityKeyPair,
    SignedPreKeyRecord,
    KyberPreKeyRecord,
    PrivateKey,
    PublicKey,
    KEMKeyPair,
} from '@signalapp/libsignal-client';

// const SIGNAL_SERVER = 'http://51.8.81.17:8080';
const SIGNAL_SERVER = 'http://localhost:8080';

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

interface VerificationSession {
    id: string;
    allowedToRequestCode: boolean;
    requestedInformation?: string[];
}

interface VerifiedSession {
    verified: boolean;
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

// Example usage for registration request
async function buildRegistrationRequest(
    sessionId: string,
    recoveryPassword: string | null,
    fcmToken: string | null
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
        number: "+18005550125",
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

function generateRegistrationId() {
    return Math.floor(Math.random() * 16380) + 1;
}

function generatePreKeyId() {
    return Math.floor(Math.random() * 16777215) + 1;
}

async function createVerificationSession(phoneNumber: string) {
    try {
        console.log('📱 Creating verification session for:', phoneNumber);
        const response = await axios.post(`${SIGNAL_SERVER}/v1/verification/session`, {
            number: phoneNumber
        });
        console.log('✅ Session created');
        console.log(response.data);
        
        return response.data;
    } catch (error: any) {
        console.error('❌ Session creation failed:', error.message);
        throw error;
    }
}

async function requestVerificationCode(sessionId: string, transport = 'SMS') {
    try {
        console.log(`📤 Requesting ${transport} verification code for session:`, sessionId);
        const response = await axios.post(
            `${SIGNAL_SERVER}/v1/verification/session/${sessionId}/code`,
            {
                transport: transport.toLocaleLowerCase(),
                client: "android-ng"
            }
        );
        console.log('✅ Verification code requested');
        console.log(response.data);
        
        return response.data;
    } catch (error: any) {
        console.error('❌ Code request failed:', error.message);
        if (error.response) {
            console.error('   📡 Status:', error.response.status);
            console.error('   💾 Response Data:', JSON.stringify(error.response.data, null, 2));
        }
        throw error;
    }
}

async function submitVerificationCode(sessionId: string, code: string) {
    try {
        console.log('🔍 Submitting verification code for session:', sessionId);
        const response = await axios.put(
            `${SIGNAL_SERVER}/v1/verification/session/${sessionId}/code`,
            { code }
        );
        console.log('✅ Code verified');
        console.log(response.data);
        
        return response.data;
    } catch (error: any) {
        console.error('❌ Code verification failed:', error.message);
        throw error;
    }
}

async function updateVerificationSession(sessionId: string) {
    try {
        console.log('🤖 Submitting captcha for session:', sessionId);
        const response = await axios.patch(
            `${SIGNAL_SERVER}/v1/verification/session/${sessionId}`,
            {
                captcha: "noop.noop.registration.noop" // Use this for testing
            }
        );
        console.log('✅ Captcha verified');
        console.log(response.data);
        
        return response.data;
    } catch (error: any) {
        console.error('❌ Captcha verification failed:', error.message);
        if (error.response) {
            console.error('   📡 Status:', error.response.status);
            console.error('   💾 Response Data:', JSON.stringify(error.response.data, null, 2));
        }
        throw error;
    }
}

async function registerUser(phoneNumber: string, password: string, sessionId: string, fcmToken: string) {
    try {
        const { request, headers } = await buildRegistrationRequest(sessionId, password, fcmToken);

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

async function main() {
    try {
        const phoneNumber = '+18005550125';
        const password = 'your_password_here';

        // Step 1: Create verification session
        const session = await createVerificationSession(phoneNumber) as VerificationSession;
        console.log('📋 Session ID:', session.id);

        // Step 2: Submit captcha
        const updatedSession = await updateVerificationSession(session.id) as VerificationSession;
        
        if (updatedSession.allowedToRequestCode) {
            // Step 3: Request verification code
            await requestVerificationCode(session.id);

            // Step 4: Submit verification code
            const verificationCode = '550125'; // Example code
            const verifiedSession = await submitVerificationCode(session.id, verificationCode) as VerifiedSession;

            if (verifiedSession.verified) {
                // Add a small delay
                await new Promise(resolve => setTimeout(resolve, 1000));
                const registration = await registerUser(
                    phoneNumber, 
                    password, 
                    session.id, 
                    "fcm-token-test"
                );
                console.log('✅ Registration complete:', registration);
            } else {
                throw new Error('Session verification failed');
            }
        } else {
            throw new Error('Session not allowed to request code: ' + 
                JSON.stringify(updatedSession.requestedInformation));
        }

    } catch (error: any) {
        console.error('\n❌ Error occurred:');
        console.error('   💥 Message:', error.message);
        if (error.response) {
            console.error('   📡 Status:', error.response.status);
            console.error('   💾 Response Data:', JSON.stringify(error.response.data, null, 2));
        }
    }
}

main();