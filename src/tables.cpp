// SPDX-License-Identifier: GPL-2.0-or-later
#include "tables.h"
#include "util.h"
#include <cstring>

const char* android_version_name(int api) {
    static const char* n[] = { "", "1.0", "1.1", "1.5 Cupcake", "1.6 Donut", "2.0 Eclair", "2.0.1 Eclair", "2.1 Eclair", "2.2 Froyo",
        "2.3 Gingerbread", "2.3.3 Gingerbread", "3.0 Honeycomb", "3.1 Honeycomb", "3.2 Honeycomb", "4.0 Ice Cream Sandwich", "4.0.3 Ice Cream Sandwich",
        "4.1 Jelly Bean", "4.2 Jelly Bean", "4.3 Jelly Bean", "4.4 KitKat", "4.4W KitKat Wear", "5.0 Lollipop", "5.1 Lollipop", "6.0 Marshmallow",
        "7.0 Nougat", "7.1 Nougat", "8.0 Oreo", "8.1 Oreo", "9 Pie", "10", "11", "12", "12L", "13", "14", "15", "16", "17" };
    if (api > 0 && api < (int)(sizeof n / sizeof n[0])) return n[api];
    if (api == 10000) return "current development";
    return nullptr;
}

const char* permission_class(const std::string& p) {
    static const char* dangerous[] = { "READ_CALENDAR","WRITE_CALENDAR","CAMERA","READ_CONTACTS","WRITE_CONTACTS","GET_ACCOUNTS",
        "ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION","ACCESS_BACKGROUND_LOCATION","RECORD_AUDIO","READ_PHONE_STATE","READ_PHONE_NUMBERS",
        "CALL_PHONE","ANSWER_PHONE_CALLS","READ_CALL_LOG","WRITE_CALL_LOG","ADD_VOICEMAIL","USE_SIP","PROCESS_OUTGOING_CALLS","BODY_SENSORS",
        "BODY_SENSORS_BACKGROUND","ACTIVITY_RECOGNITION","SEND_SMS","RECEIVE_SMS","READ_SMS","RECEIVE_WAP_PUSH","RECEIVE_MMS",
        "READ_EXTERNAL_STORAGE","WRITE_EXTERNAL_STORAGE","ACCESS_MEDIA_LOCATION","ACCEPT_HANDOVER","UWB_RANGING","BLUETOOTH_SCAN",
        "BLUETOOTH_CONNECT","BLUETOOTH_ADVERTISE","NEARBY_WIFI_DEVICES","POST_NOTIFICATIONS","READ_MEDIA_IMAGES","READ_MEDIA_VIDEO",
        "READ_MEDIA_AUDIO","READ_MEDIA_VISUAL_USER_SELECTED","RANGING", nullptr };
    static const char* special[] = { "SYSTEM_ALERT_WINDOW","WRITE_SETTINGS","MANAGE_EXTERNAL_STORAGE","REQUEST_INSTALL_PACKAGES",
        "PACKAGE_USAGE_STATS","BIND_ACCESSIBILITY_SERVICE","BIND_NOTIFICATION_LISTENER_SERVICE","BIND_DEVICE_ADMIN","SCHEDULE_EXACT_ALARM",
        "USE_FULL_SCREEN_INTENT","QUERY_ALL_PACKAGES","REQUEST_IGNORE_BATTERY_OPTIMIZATIONS","MANAGE_MEDIA","ACCESS_NOTIFICATION_POLICY",
        "BIND_VPN_SERVICE","BIND_INPUT_METHOD","BIND_AUTOFILL_SERVICE","BIND_WALLPAPER","BIND_QUICK_SETTINGS_TILE","MANAGE_OWN_CALLS",
        "USE_EXACT_ALARM","RUN_USER_INITIATED_JOBS","BIND_CARRIER_SERVICES",nullptr };
    static const char* signature[] = { "READ_LOGS","INSTALL_PACKAGES","DELETE_PACKAGES","WRITE_SECURE_SETTINGS","MOUNT_UNMOUNT_FILESYSTEMS",
        "READ_PRIVILEGED_PHONE_STATE","MODIFY_PHONE_STATE","REBOOT","DEVICE_POWER","STATUS_BAR","INTERACT_ACROSS_USERS","INTERACT_ACROSS_USERS_FULL",
        "MANAGE_USERS","CHANGE_COMPONENT_ENABLED_STATE","BATTERY_STATS","DUMP","SET_TIME","WRITE_MEDIA_STORAGE","CAPTURE_AUDIO_OUTPUT",
        "MASTER_CLEAR","UPDATE_DEVICE_STATS","GRANT_RUNTIME_PERMISSIONS","PACKAGE_VERIFICATION_AGENT","LOCAL_MAC_ADDRESS","BIND_JOB_SERVICE", nullptr };
    static const char* normal[] = { "INTERNET","ACCESS_NETWORK_STATE","ACCESS_WIFI_STATE","CHANGE_WIFI_STATE","CHANGE_NETWORK_STATE","WAKE_LOCK",
        "VIBRATE","FOREGROUND_SERVICE","RECEIVE_BOOT_COMPLETED","BLUETOOTH","BLUETOOTH_ADMIN","NFC","NFC_TRANSACTION_EVENT","NFC_PREFERRED_PAYMENT_INFO",
        "USE_BIOMETRIC","USE_FINGERPRINT","REQUEST_DELETE_PACKAGES","SET_WALLPAPER","SET_WALLPAPER_HINTS","MODIFY_AUDIO_SETTINGS",
        "EXPAND_STATUS_BAR","KILL_BACKGROUND_PROCESSES","READ_SYNC_SETTINGS","WRITE_SYNC_SETTINGS","READ_SYNC_STATS","ACCESS_LOCATION_EXTRA_COMMANDS",
        "TRANSMIT_IR","GET_PACKAGE_SIZE","CHANGE_WIFI_MULTICAST_STATE","DISABLE_KEYGUARD","REORDER_TASKS","BROADCAST_STICKY","SET_ALARM",
        "REQUEST_COMPANION_RUN_IN_BACKGROUND","REQUEST_COMPANION_USE_DATA_IN_BACKGROUND","INSTALL_SHORTCUT","UNINSTALL_SHORTCUT",
        "CALL_COMPANION_APP","CREDENTIAL_MANAGER_QUERY_CANDIDATE_CREDENTIALS","CREDENTIAL_MANAGER_SET_ORIGIN",
        "DETECT_SCREEN_CAPTURE","ENFORCE_UPDATE_OWNERSHIP","HIDE_OVERLAY_WINDOWS","HIGH_SAMPLING_RATE_SENSORS","PERSISTENT_ACTIVITY",
        "READ_BASIC_PHONE_STATE","REQUEST_OBSERVE_COMPANION_DEVICE_PRESENCE","REQUEST_PASSWORD_COMPLEXITY",
        "RESTART_PACKAGES","UPDATE_PACKAGES_WITHOUT_USER_ACTION","USE_CREDENTIALS","MANAGE_ACCOUNTS","AUTHENTICATE_ACCOUNTS","READ_PROFILE",
        "WRITE_PROFILE","SUBSCRIBED_FEEDS_READ","DELIVER_COMPANION_MESSAGES","DETECT_SCREEN_RECORDING", nullptr };
    if (starts_with(p, "android.permission.FOREGROUND_SERVICE_")) return "normal";
    if (!starts_with(p, "android.permission.")) {
        if (p == "com.android.launcher.permission.INSTALL_SHORTCUT" || p == "com.google.android.c2dm.permission.RECEIVE" ||
            p == "com.google.android.gms.permission.AD_ID" || p == "com.android.alarm.permission.SET_ALARM") return "normal";
        return nullptr;
    }
    std::string s = p.substr(19);
    for (int i = 0; dangerous[i]; i++) if (s == dangerous[i]) return "DANGEROUS";
    for (int i = 0; special[i]; i++) if (s == special[i]) return "special access";
    for (int i = 0; signature[i]; i++) if (s == signature[i]) return "signature/privileged";
    for (int i = 0; normal[i]; i++) if (s == normal[i]) return "normal";
    return nullptr;
}

std::string protection_level_string(uint32_t v) {
    static const char* base[] = { "normal", "dangerous", "signature", "signatureOrSystem", "internal" };
    std::string s = (v & 0xF) < 5 ? base[v & 0xF] : strf("base%u", v & 0xF);
    static const struct { uint32_t f; const char* n; } fl[] = {
        {0x10,"privileged"},{0x20,"development"},{0x40,"appop"},{0x80,"pre23"},{0x100,"installer"},{0x200,"verifier"},
        {0x400,"preinstalled"},{0x800,"setup"},{0x1000,"instant"},{0x2000,"runtime"},{0x4000,"oem"},{0x8000,"vendorPrivileged"},
        {0x10000,"textClassifier"},{0x40000,"incidentReportApprover"},{0x80000,"appPredictor"},{0x200000,"companion"},
        {0x400000,"retailDemo"},{0x800000,"recents"},{0x1000000,"role"},{0x2000000,"knownSigner"} };
    for (auto& f : fl) if (v & f.f) s += "|" + std::string(f.n);
    return s;
}
