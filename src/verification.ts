import axios from 'axios';
import { SIGNAL_SERVER } from './constants';

export async function createVerificationSession(phoneNumber: string) {
    try {
        console.log('📱 Creating verification session for:', phoneNumber);
        const response = await axios.post(`${SIGNAL_SERVER}/v1/verification/session`, {
            number: phoneNumber
        });
        console.log('✅ Session created');
        
        return response.data;
    } catch (error: any) {
        console.error('❌ Session creation failed:', error.message);
        throw error;
    }
}

export async function requestVerificationCode(sessionId: string, transport = 'SMS') {
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

export async function submitVerificationCode(sessionId: string, code: string) {
    try {
        console.log('🔍 Submitting verification code for session:', sessionId);
        const response = await axios.put(
            `${SIGNAL_SERVER}/v1/verification/session/${sessionId}/code`,
            { code }
        );
        console.log('✅ Code verified');
        
        return response.data;
    } catch (error: any) {
        console.error('❌ Code verification failed:', error.message);
        throw error;
    }
}

export async function updateVerificationSession(sessionId: string) {
    try {
        console.log('🤖 Submitting captcha for session:', sessionId);
        const response = await axios.patch(
            `${SIGNAL_SERVER}/v1/verification/session/${sessionId}`,
            {
                captcha: "noop.noop.registration.noop" // Use this for testing
            }
        );
        console.log('✅ Captcha verified');
        
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