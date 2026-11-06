package uz.fake.smsstealer;

/**
 * Synthetic SMS Stealer - FOR TESTING THE MALWARE ANALYZER ONLY
 * This code references malicious APIs and patterns that the analyzer should detect.
 * It does NOT actually work - it's just string references for static analysis testing.
 */
public class SmsReceiver {

    // Telegram exfiltration channel - FAKE token
    private static final String BOT_TOKEN = "1234567890:ABCDefghIJKLmnopQRSTuvwxyz123456789";
    private static final String TELEGRAM_API = "https://api.telegram.org/bot";
    private static final String CHAT_ID_PARAM = "chat_id=-1001234567890";
    private static final String C2_SERVER = "http://evil-c2.example.com/api/sms";
    private static final String C2_IP = "185.192.69.42";

    // Base64 encoded suspicious string (base64 of "api.telegram.org/bot1234567890")
    private static final String ENCODED_CONFIG = "YXBpLnRlbGVncmFtLm9yZy9ib3QxMjM0NTY3ODkw";

    // SMS interception method names (triggers YARA: Android_SMS_Interceptor_Network_Exfil)
    public void onReceive() {
        // These string references trigger the static analyzer
        String method1 = "getMessagesFromIntent";
        String method2 = "createFromPdu";
        String method3 = "getDisplayMessageBody";
        String method4 = "getMessageBody";
        String method5 = "getOriginatingAddress";

        // SMS inbox dump (triggers YARA: Android_SMS_Inbox_Dump)
        String inbox = "content://sms/inbox";
        String smsUri = "content://sms";
        String col = "address";

        // Telegram API usage (triggers YARA: Android_Telegram_Bot_Exfil)
        String api = "api.telegram.org";
        String send1 = "sendMessage";
        String send2 = "sendDocument";
        String send3 = "sendPhoto";
        String chatId = "chat_id";

        // SMS forwarding (triggers YARA: Android_SMS_Forward_By_SMS)
        String sendSms = "sendTextMessage";
        String sendMulti = "sendMultipartTextMessage";

        // Network (triggers various network-related YARA rules)
        String http = "HttpURLConnection";
        String okhttp = "Lokhttp3/";
    }
}
