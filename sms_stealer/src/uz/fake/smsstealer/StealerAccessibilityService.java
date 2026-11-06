package uz.fake.smsstealer;

/**
 * Accessibility service abuse - triggers accessibility-related detections
 */
public class StealerAccessibilityService {

    // Accessibility service type reference (triggers YARA: Android_Accessibility_Abuse)
    private static final String SERVICE_TYPE = "Landroid/accessibilityservice/AccessibilityService;";

    public void performActions() {
        // These trigger accessibility abuse detection
        String action1 = "performGlobalAction";
        String action2 = "dispatchGesture";
        String action3 = "getRootInActiveWindow";
        String action4 = "findAccessibilityNodeInfosByViewId";
        String action5 = "findAccessibilityNodeInfosByText";
    }

    // Overlay phishing (triggers YARA: Android_Overlay_Phishing)
    public void showOverlay() {
        String overlayCheck = "canDrawOverlays";
        String overlaySettings = "android.settings.action.MANAGE_OVERLAY_PERMISSION";
        String windowManager = "Landroid/view/WindowManager;";
        String addView = "addView";
        String loadUrl = "loadUrl";
        String loadData = "loadDataWithBaseURL";
    }

    // Icon hiding (triggers hidden icon detection)
    public void hideIcon() {
        String hide = "setComponentEnabledSetting";
    }

    // Device admin abuse (triggers YARA: Android_Device_Admin_Abuse)
    public void adminAbuse() {
        String dpm = "Landroid/app/admin/DevicePolicyManager;";
        String lock = "lockNow";
        String wipe = "wipeData";
        String resetPwd = "resetPassword";
    }

    // Dropper behavior (triggers YARA: Android_Dropper_Installs_APK)
    public void dropPayload() {
        String mime = "application/vnd.android.package-archive";
        String install = "REQUEST_INSTALL_PACKAGES";
        String installer = "Landroid/content/pm/PackageInstaller;";
        String assets = "getAssets";
    }
}
