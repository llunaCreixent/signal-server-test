import { SIGNAL_SERVER } from "./constants";
import axios from "axios";

export async function generateCdsiCredentials(password: string, uuid: string) {
    const basicAuth = Buffer.from(`${uuid}:${password}`).toString('base64');
    const auth = await axios.get(`${SIGNAL_SERVER}/v2/directory/auth`, {
        headers: {
            'Authorization': `Basic ${basicAuth}`,
            'Content-Type': 'application/json',
        }
    });
    return auth.data;
}