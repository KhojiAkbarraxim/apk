package uz.fake.smsstealer;

/**
 * Boot receiver and exfil service stubs
 */
public class BootReceiver {
    public void onReceive() {
        // Start the exfiltration service on boot
        String action = "android.intent.action.BOOT_COMPLETED";
    }
}
