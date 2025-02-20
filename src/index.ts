import { createVerificationSession, requestVerificationCode, submitVerificationCode, updateVerificationSession } from './verification';
import { registerUser } from './registration';

interface VerificationSession {
    id: string;
    allowedToRequestCode: boolean;
    requestedInformation?: string[];
}

interface VerifiedSession {
    verified: boolean;
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