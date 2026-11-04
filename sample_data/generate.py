"""Generate the sample businesses used for demos, tests, and LinkedIn posts.

Why synthetic businesses, grounded in real data
-----------------------------------------------
The brief forbids storing any real business's data, so the *businesses* are
fictional. Everything they run, however, is real and dated:

* operating systems and their end-of-life dates come from the endoflife.date
  snapshot in data/reference/eol_table.csv (e.g. Windows 10 22H2 ended
  2025-10-14; Windows 11 24H2 Home/Pro ended 2026-10-13);
* vulnerable products come from the CISA KEV snapshot in
  data/reference/kev_smb_snapshot.csv (e.g. TP-Link TL-WR841N, CVE-2023-50224;
  ConnectWise ScreenConnect; WinRAR, CVE-2025-8088);
* the business mix mirrors Chicago's active license counts in
  data/reference/chicago_license_counts_by_type.csv (Retail Food Establishment
  and Children's Services Facility are among the largest small-business
  categories).

Each business ships with ``expected_findings.yaml``: hand-labelled ground truth
written from the rule specs (not from engine output). From Week 2 the rules
engine is tested against these labels, so the sample data is the test oracle.

Run:  python sample_data/generate.py   (deterministic: fixed seed and as-of date)
"""

from __future__ import annotations

import csv
import random
from datetime import date, timedelta
from pathlib import Path

import yaml
from faker import Faker

AS_OF = date(2026, 11, 4)  # every relative date is computed from this, so tests are stable
SEED = 20261102            # project start date
OUT = Path(__file__).resolve().parent / "businesses"

fake = Faker("en_US")
Faker.seed(SEED)
rng = random.Random(SEED)


def d(days_ago: int) -> str:
    return (AS_OF - timedelta(days=days_ago)).isoformat()


def jitter(days_ago: int, spread: int = 3) -> str:
    return d(days_ago + rng.randint(0, spread))


def created(min_years: float = 0.5, max_years: float = 5) -> str:
    return fake.date_between(
        start_date=AS_OF - timedelta(days=int(365 * max_years)),
        end_date=AS_OF - timedelta(days=int(365 * min_years)),
    ).isoformat()


TEMPLATE_FIELDS = {
    "users_permissions": ["user_id", "account_type", "is_admin", "mfa_enabled", "status", "created_date", "last_login_date", "role_or_department"],
    "firewall_rules": ["rule_id", "enabled", "action", "direction", "source", "destination", "service_or_port", "comment"],
    "patch_inventory": ["device_id", "device_type", "os_name", "os_version", "auto_update_enabled", "last_patch_date", "pending_critical_updates", "key_software_name", "key_software_version", "vendor_supported"],
    "endpoint_protection": ["device_id", "device_type", "protection_product", "protection_enabled", "definitions_date", "disk_encryption", "screen_lock", "last_seen_date"],
    "email_domain_check": ["domain", "mx_provider", "spf_present", "spf_all_qualifier", "dmarc_present", "dmarc_policy", "dmarc_rua_present", "dkim_found", "checked_on"],
    "backup_jobs": ["job_id", "source_system", "destination_type", "schedule", "last_success_date", "last_restore_test_date", "encrypted", "retention_days"],
}

FICTIONAL = "Fictional business created for testing. Any resemblance to a real business is coincidental."


# --------------------------------------------------------------------------- A
def taqueria() -> dict:
    cashiers = [
        {"user_id": f"cashier-{i}", "account_type": "staff", "is_admin": "N", "mfa_enabled": "N",
         "status": "active", "created_date": created(0.3, 3), "last_login_date": jitter(1, 4), "role_or_department": "Register"}
        for i in range(1, 4)
    ]
    return {
        "slug": "taqueria_luna_azul",
        "profile": {
            "name": "Taqueria Luna Azul (fictional)",
            "segment": "restaurant_food",
            "chicago_license_category": "Retail Food Establishment",
            "owner_persona": fake.first_name() + " (fictional)",
            "story": ("Family-run taqueria, 8 staff, open 7 days. Square on an iPad at the counter, a Windows "
                      "back-office PC for payroll and online-order tablets. A nephew 'does the computers'. The "
                      "register reseller installed a remote-support tool years ago, and the owner opened Remote "
                      "Desktop on the router so they could do payroll from home."),
            "designed_weaknesses": [
                "Shared register login and everyone is an administrator",
                "Remote Desktop (3389) forwarded from the internet to the office PC; no MFA",
                "ConnectWise ScreenConnect client left installed (product is in CISA KEV)",
                "Back-office PC on Windows 11 24H2 Home, which reached end of servicing on 2026-10-13 (owner thinks it is current)",
                "Customer Wi-Fi on the same network as the register",
                "Cloud sales data never test-restored",
            ],
            "disclaimer": FICTIONAL,
        },
        "answers": {
            "bp_business_type": "restaurant_food", "bp_staff_count": "6_10", "bp_days_open": "7",
            "bp_daily_sales_band": "3000_6000", "bp_critical_systems": ["pos_payments", "online_orders", "payroll"],
            "bp_paper_fallback": "no", "bp_sensitive_data": ["none"], "bp_it_owner": "family",
            "bp_device_count": "3_5", "bp_cyber_insurance": "dont_know",
            "iam_shared_logins": "yes", "iam_former_staff_access": "dont_know", "iam_mfa_email": "yes",
            "iam_mfa_banking": "yes", "iam_mfa_pos_admin": "no", "iam_admin_count": "everyone",
            "iam_password_manager": "no", "iam_phished_before": "no", "iam_payment_verification": "no",
            "iam_unique_passwords": "no", "iam_account_list": "no", "iam_security_training": "no",
            "net_guest_wifi_separate": "no", "net_router_default_password": "yes", "net_router_admin_logged_in": "no",
            "net_router_updated": "dont_know", "net_remote_access_used": "yes", "net_remote_access_mfa": "no",
            "net_remote_tool_always_on": "yes", "net_dns_filtering": "no",
            "pat_auto_updates": "yes", "pat_old_os": "no", "pat_pos_supported": "yes",
            "pat_update_reminder_month": "no", "pat_browser_updates": "yes", "pat_software_list": "no",
            "end_antivirus": "yes", "end_encryption": "dont_know", "end_screen_lock": "no",
            "end_personal_phones_email": "yes", "end_old_devices": "no", "end_device_list": "no",
            "bkp_backed_up": "yes", "bkp_locations": ["cloud"], "bkp_restore_tested": "no",
            "bkp_recovery_time": "a_day", "bkp_contact_list": "yes", "bkp_incident_owner": "yes", "bkp_vendor_list": "no",
            "bp_biometrics": "yes", "bp_email_domain": "lunaazul-taqueria.example", "iam_breach_check": "no",
        },
        "uploads": {
            "users_permissions": [
                {"user_id": "owner", "account_type": "admin", "is_admin": "Y", "mfa_enabled": "Y", "status": "active",
                 "created_date": "2019-04-01", "last_login_date": d(0), "role_or_department": "Owner"},
                {"user_id": "manager-1", "account_type": "staff", "is_admin": "Y", "mfa_enabled": "N", "status": "active",
                 "created_date": created(1, 4), "last_login_date": d(1), "role_or_department": "Shift manager"},
                *cashiers,
                {"user_id": "register-shared", "account_type": "shared", "is_admin": "N", "mfa_enabled": "N", "status": "active",
                 "created_date": "2019-04-01", "last_login_date": d(0), "role_or_department": "Register"},
                {"user_id": "former-cashier", "account_type": "staff", "is_admin": "N", "mfa_enabled": "N", "status": "active",
                 "created_date": "2024-05-12", "last_login_date": d(137), "role_or_department": ""},
            ],
            "firewall_rules": [
                {"rule_id": "1", "enabled": "Y", "action": "allow", "direction": "outbound", "source": "lan", "destination": "any", "service_or_port": "any", "comment": "Default outbound"},
                {"rule_id": "2", "enabled": "Y", "action": "allow", "direction": "inbound", "source": "wan", "destination": "192.168.0.25", "service_or_port": "3389", "comment": "Owner payroll from home"},
                {"rule_id": "3", "enabled": "Y", "action": "deny", "direction": "inbound", "source": "any", "destination": "any", "service_or_port": "any", "comment": "Default deny"},
            ],
            "patch_inventory": [
                {"device_id": "office-pc", "device_type": "desktop", "os_name": "Windows", "os_version": "11 24H2 (W)",
                 "auto_update_enabled": "Y", "last_patch_date": d(20), "pending_critical_updates": 0,
                 "key_software_name": "ConnectWise ScreenConnect Client", "key_software_version": "23.9.8", "vendor_supported": "unknown"},
                {"device_id": "counter-ipad", "device_type": "tablet", "os_name": "iPadOS", "os_version": "18",
                 "auto_update_enabled": "Y", "last_patch_date": d(12), "pending_critical_updates": 0,
                 "key_software_name": "Square Point of Sale", "key_software_version": "6.x", "vendor_supported": "Y"},
                {"device_id": "orders-tablet", "device_type": "tablet", "os_name": "Android", "os_version": "14",
                 "auto_update_enabled": "Y", "last_patch_date": d(25), "pending_critical_updates": 0,
                 "key_software_name": "Online ordering app", "key_software_version": "", "vendor_supported": "Y"},
            ],
            "endpoint_protection": [
                {"device_id": "office-pc", "device_type": "desktop", "protection_product": "Microsoft Defender Antivirus", "protection_enabled": "Y",
                 "definitions_date": d(1), "disk_encryption": "unknown", "screen_lock": "N", "last_seen_date": d(0)},
                {"device_id": "counter-ipad", "device_type": "tablet", "protection_product": "", "protection_enabled": "Y",
                 "definitions_date": "", "disk_encryption": "Y", "screen_lock": "Y", "last_seen_date": d(0)},
                {"device_id": "owner-phone", "device_type": "phone", "protection_product": "", "protection_enabled": "Y",
                 "definitions_date": "", "disk_encryption": "Y", "screen_lock": "Y", "last_seen_date": d(0)},
            ],
            "backup_jobs": [
                {"job_id": "1", "source_system": "square sales data", "destination_type": "cloud", "schedule": "daily",
                 "last_success_date": d(0), "last_restore_test_date": "", "encrypted": "Y", "retention_days": 365},
            ],
        },
        "lookups": {"email_domain_check": [{"domain": "lunaazul-taqueria.example", "mx_provider": "google", "spf_present": "Y", "spf_all_qualifier": "~all", "dmarc_present": "Y", "dmarc_policy": "none", "dmarc_rua_present": "N", "dkim_found": "Y", "checked_on": AS_OF.isoformat()}]},
        "expected_legal_flags": ["LEG-001", "LEG-003"],
        "expected": [
            "IAM-001", "IAM-003", "IAM-004", "IAM-006", "IAM-007", "IAM-008", "IAM-009", "IAM-010", "IAM-011",
            "IAM-012", "IAM-013", "IAM-014", "IAM-015",
            "NET-001", "NET-002", "NET-003", "NET-004", "NET-005", "NET-006", "NET-011", "NET-012",
            "PAT-006", "PAT-007", "PAT-008", "PAT-010",
            "END-002", "END-003", "END-004", "END-009", "END-011",
            "BKP-003", "BKP-010",
            "IAM-016", "NET-014",
        ],
    }


# --------------------------------------------------------------------------- B
def daycare() -> dict:
    return {
        "slug": "little_sprouts_daycare",
        "profile": {
            "name": "Little Sprouts Home Daycare (fictional)",
            "segment": "childcare",
            "chicago_license_category": "Children's Services Facility License",
            "owner_persona": fake.first_name() + " (fictional)",
            "story": ("Licensed home daycare, director plus two assistants, open 5 days. Enrollment forms, "
                      "immunization records and parent payment details live on one family laptop that the "
                      "director's kids also use. Google Workspace for email. No backups."),
            "designed_weaknesses": [
                "No backups of enrollment and health records",
                "Shared family laptop, not encrypted, Windows 11 23H2 Home (end of servicing 2025-11-11)",
                "No MFA on Google Workspace; a former assistant's account still active",
                "WinRAR installed (WinRAR has entries in CISA KEV)",
                "Old phone with parent contacts in a drawer",
            ],
            "disclaimer": FICTIONAL,
        },
        "answers": {
            "bp_business_type": "childcare", "bp_staff_count": "2_5", "bp_days_open": "5",
            "bp_daily_sales_band": "500_1500", "bp_critical_systems": ["records", "email"],
            "bp_paper_fallback": "yes", "bp_sensitive_data": ["childrens_records", "health_info"], "bp_it_owner": "me",
            "bp_device_count": "1_2", "bp_cyber_insurance": "no",
            "iam_shared_logins": "yes", "iam_former_staff_access": "no", "iam_mfa_email": "no",
            "iam_mfa_banking": "yes", "iam_mfa_pos_admin": "dont_know", "iam_admin_count": "everyone",
            "iam_password_manager": "no", "iam_phished_before": "yes", "iam_payment_verification": "yes",
            "iam_unique_passwords": "no", "iam_account_list": "no", "iam_security_training": "no",
            "net_guest_wifi_separate": "dont_know", "net_router_default_password": "dont_know",
            "net_router_admin_logged_in": "no", "net_router_updated": "dont_know",
            "net_remote_access_used": "no", "net_dns_filtering": "dont_know",
            "pat_auto_updates": "yes", "pat_old_os": "no", "pat_pos_supported": "dont_know",
            "pat_update_reminder_month": "yes", "pat_browser_updates": "yes", "pat_software_list": "no",
            "end_antivirus": "yes", "end_encryption": "no", "end_screen_lock": "no",
            "end_personal_phones_email": "yes", "end_old_devices": "yes", "end_device_list": "no",
            "bkp_backed_up": "no", "bkp_recovery_time": "dont_know", "bkp_contact_list": "no",
            "bkp_incident_owner": "no", "bkp_vendor_list": "no",
            "bp_biometrics": "no", "bp_email_domain": "littlesprouts-daycare.example", "iam_breach_check": "dont_know",
        },
        "uploads": {
            "users_permissions": [
                {"user_id": "director", "account_type": "staff", "is_admin": "Y", "mfa_enabled": "N", "status": "active",
                 "created_date": "2020-08-17", "last_login_date": d(0), "role_or_department": "Director"},
                {"user_id": "assistant-1", "account_type": "staff", "is_admin": "N", "mfa_enabled": "N", "status": "active",
                 "created_date": created(0.5, 2), "last_login_date": jitter(2), "role_or_department": "Assistant teacher"},
                {"user_id": "assistant-2", "account_type": "staff", "is_admin": "N", "mfa_enabled": "N", "status": "active",
                 "created_date": created(0.5, 2), "last_login_date": jitter(3), "role_or_department": "Assistant teacher"},
                {"user_id": "former-assistant", "account_type": "staff", "is_admin": "N", "mfa_enabled": "N", "status": "active",
                 "created_date": "2023-01-09", "last_login_date": d(214), "role_or_department": "Assistant teacher"},
                {"user_id": "classroom", "account_type": "shared", "is_admin": "N", "mfa_enabled": "N", "status": "active",
                 "created_date": "2021-09-01", "last_login_date": d(1), "role_or_department": "Classroom tablet"},
            ],
            "patch_inventory": [
                {"device_id": "family-laptop", "device_type": "laptop", "os_name": "Windows", "os_version": "11 23H2 (W)",
                 "auto_update_enabled": "N", "last_patch_date": d(76), "pending_critical_updates": 3,
                 "key_software_name": "WinRAR", "key_software_version": "6.02", "vendor_supported": "Y"},
                {"device_id": "director-phone", "device_type": "phone", "os_name": "iOS", "os_version": "18",
                 "auto_update_enabled": "Y", "last_patch_date": d(9), "pending_critical_updates": 0,
                 "key_software_name": "Gmail", "key_software_version": "", "vendor_supported": "Y"},
            ],
            "endpoint_protection": [
                {"device_id": "family-laptop", "device_type": "laptop", "protection_product": "Microsoft Defender Antivirus", "protection_enabled": "Y",
                 "definitions_date": d(33), "disk_encryption": "N", "screen_lock": "N", "last_seen_date": d(0)},
                {"device_id": "old-phone", "device_type": "phone", "protection_product": "", "protection_enabled": "N",
                 "definitions_date": "", "disk_encryption": "unknown", "screen_lock": "unknown", "last_seen_date": "2025-05-30"},
                {"device_id": "director-phone", "device_type": "phone", "protection_product": "", "protection_enabled": "Y",
                 "definitions_date": "", "disk_encryption": "Y", "screen_lock": "Y", "last_seen_date": d(0)},
            ],
        },
        "lookups": {"email_domain_check": [{"domain": "littlesprouts-daycare.example", "mx_provider": "google", "spf_present": "N", "spf_all_qualifier": "none", "dmarc_present": "N", "dmarc_policy": "missing", "dmarc_rua_present": "N", "dkim_found": "unknown", "checked_on": AS_OF.isoformat()}]},
        "expected_legal_flags": ["LEG-002", "LEG-004", "LEG-005"],
        "expected": [
            "IAM-001", "IAM-002", "IAM-004", "IAM-006", "IAM-007", "IAM-008", "IAM-009", "IAM-010", "IAM-011",
            "IAM-012", "IAM-014",
            "NET-001", "NET-005", "NET-006", "NET-011",
            "PAT-001", "PAT-003", "PAT-004", "PAT-005", "PAT-006", "PAT-008", "PAT-010",
            "END-002", "END-003", "END-004", "END-005", "END-007", "END-008", "END-009", "END-010", "END-011",
            "BKP-001", "BKP-004", "BKP-005", "BKP-006", "BKP-010",
            "IAM-016", "NET-013", "NET-015",
        ],
    }


# --------------------------------------------------------------------------- C
def salon() -> dict:
    return {
        "slug": "fade_and_shine_salon",
        "profile": {
            "name": "Fade & Shine Salon (fictional)",
            "segment": "salon_barber",
            "chicago_license_category": "Limited Business License",
            "owner_persona": fake.first_name() + " (fictional)",
            "story": ("Four-chair salon and barbershop, open 6 days. One front-desk Windows 10 PC runs the "
                      "booking website and the camera viewer. The router came from a friend and was never "
                      "updated. Nobody looks after the computers."),
            "designed_weaknesses": [
                "Front-desk PC on Windows 10 22H2 (end of support 2025-10-14), no antivirus, updates off",
                "TP-Link TL-WR841N router on old firmware (model has CVE-2023-50224 in CISA KEV); DMZ allow-all rule",
                "Camera DVR web page forwarded to the internet on 8080",
                "Only backup is on the same PC plus an unencrypted USB drive in the drawer, 7-day retention",
                "Guest Wi-Fi allowed to reach the business network for lobby-TV casting (contradicts the owner's answer)",
                "No MFA on online banking",
            ],
            "disclaimer": FICTIONAL,
        },
        "answers": {
            "bp_business_type": "salon_barber", "bp_staff_count": "2_5", "bp_days_open": "6",
            "bp_daily_sales_band": "1500_3000", "bp_critical_systems": ["booking", "pos_payments"],
            "bp_paper_fallback": "yes", "bp_sensitive_data": ["none"], "bp_it_owner": "nobody",
            "bp_device_count": "1_2", "bp_cyber_insurance": "no",
            "iam_shared_logins": "yes", "iam_former_staff_access": "no", "iam_mfa_email": "dont_know",
            "iam_mfa_banking": "no", "iam_mfa_pos_admin": "yes", "iam_admin_count": "dont_know",
            "iam_password_manager": "no", "iam_phished_before": "no", "iam_payment_verification": "yes",
            "iam_unique_passwords": "dont_know", "iam_account_list": "no", "iam_security_training": "no",
            "net_guest_wifi_separate": "yes", "net_router_default_password": "yes", "net_router_admin_logged_in": "no",
            "net_router_updated": "longer", "net_remote_access_used": "no", "net_dns_filtering": "no",
            "pat_auto_updates": "no", "pat_old_os": "yes", "pat_pos_supported": "yes",
            "pat_update_reminder_month": "yes", "pat_browser_updates": "dont_know", "pat_software_list": "no",
            "end_antivirus": "no", "end_encryption": "no", "end_screen_lock": "no",
            "end_personal_phones_email": "yes", "end_old_devices": "no", "end_device_list": "no",
            "bkp_backed_up": "yes", "bkp_locations": ["same_computer", "external_drive_onsite"], "bkp_restore_tested": "no",
            "bkp_recovery_time": "days", "bkp_contact_list": "no", "bkp_incident_owner": "no", "bkp_vendor_list": "no",
            "bp_biometrics": "dont_know", "iam_breach_check": "no",
        },
        "uploads": {
            "users_permissions": [
                {"user_id": "owner", "account_type": "admin", "is_admin": "Y", "mfa_enabled": "unknown", "status": "active",
                 "created_date": "2018-02-20", "last_login_date": d(6), "role_or_department": "Owner"},
                {"user_id": "front-desk", "account_type": "shared", "is_admin": "Y", "mfa_enabled": "unknown", "status": "active",
                 "created_date": "2018-02-20", "last_login_date": d(0), "role_or_department": "Front desk (all stylists)"},
            ],
            "firewall_rules": [
                {"rule_id": "dmz", "enabled": "Y", "action": "allow", "direction": "inbound", "source": "any", "destination": "any", "service_or_port": "any", "comment": ""},
                {"rule_id": "fwd-1", "enabled": "Y", "action": "allow", "direction": "inbound", "source": "wan", "destination": "192.168.0.50", "service_or_port": "8080", "comment": "Camera DVR"},
                {"rule_id": "guest", "enabled": "Y", "action": "allow", "direction": "outbound", "source": "guest", "destination": "wan", "service_or_port": "any", "comment": "Guest internet only"},
                {"rule_id": "guest-tv", "enabled": "Y", "action": "allow", "direction": "outbound", "source": "guest", "destination": "lan", "service_or_port": "any", "comment": "Let clients cast to the lobby TV"},
            ],
            "patch_inventory": [
                {"device_id": "front-pc", "device_type": "desktop", "os_name": "Windows", "os_version": "10 22H2",
                 "auto_update_enabled": "N", "last_patch_date": "2025-10-14", "pending_critical_updates": 12,
                 "key_software_name": "Booking website (browser)", "key_software_version": "", "vendor_supported": "Y"},
                {"device_id": "router", "device_type": "router", "os_name": "TP-Link firmware", "os_version": "TL-WR841N v14 (2021)",
                 "auto_update_enabled": "N", "last_patch_date": "2021-06-30", "pending_critical_updates": 0,
                 "key_software_name": "TP-Link TL-WR841N", "key_software_version": "v14", "vendor_supported": "N"},
            ],
            "endpoint_protection": [
                {"device_id": "front-pc", "device_type": "desktop", "protection_product": "", "protection_enabled": "N",
                 "definitions_date": "", "disk_encryption": "N", "screen_lock": "N", "last_seen_date": d(0)},
                {"device_id": "stylist-tablet", "device_type": "tablet", "protection_product": "", "protection_enabled": "N",
                 "definitions_date": "", "disk_encryption": "Y", "screen_lock": "Y", "last_seen_date": d(1)},
            ],
            "backup_jobs": [
                {"job_id": "1", "source_system": "front-pc documents", "destination_type": "same_device", "schedule": "weekly",
                 "last_success_date": "2026-09-01", "last_restore_test_date": "", "encrypted": "N", "retention_days": 7},
                {"job_id": "2", "source_system": "front-pc documents", "destination_type": "local_external", "schedule": "manual",
                 "last_success_date": "2026-05-01", "last_restore_test_date": "", "encrypted": "N", "retention_days": 180},
            ],
        },
        "lookups": {},
        "expected_legal_flags": ["LEG-001", "LEG-003"],
        "expected": [
            "IAM-001", "IAM-002", "IAM-005", "IAM-007", "IAM-009", "IAM-010", "IAM-011", "IAM-012", "IAM-014",
            "NET-005", "NET-006", "NET-007", "NET-008", "NET-009", "NET-010", "NET-011",
            "PAT-001", "PAT-002", "PAT-004", "PAT-005", "PAT-006", "PAT-007", "PAT-008", "PAT-009", "PAT-010",
            "END-001", "END-002", "END-003", "END-004", "END-006", "END-009", "END-011",
            "BKP-002", "BKP-003", "BKP-004", "BKP-005", "BKP-006", "BKP-007", "BKP-008", "BKP-009", "BKP-010",
            "IAM-016",
        ],
    }


# --------------------------------------------------------------------------- D
def pantry() -> dict:
    """Control case: a well-run organization. Guards against rules that over-fire."""
    return {
        "slug": "northside_community_pantry",
        "profile": {
            "name": "Northside Community Pantry (fictional, control case)",
            "segment": "nonprofit_faith",
            "chicago_license_category": "Not-For-Profit Club",
            "owner_persona": fake.first_name() + " (fictional)",
            "story": ("Volunteer-run food pantry whose board treasurer works in IT. Microsoft 365 with MFA, "
                      "managed laptops, cloud plus offline backups tested every quarter. Included so tests "
                      "prove the rules stay quiet when the basics are in place."),
            "designed_weaknesses": ["Volunteers read pantry email on personal phones (accepted risk)"],
            "disclaimer": FICTIONAL,
        },
        "answers": {
            "bp_business_type": "nonprofit_faith", "bp_staff_count": "6_10", "bp_days_open": "3",
            "bp_daily_sales_band": "prefer_not", "bp_critical_systems": ["email", "records"],
            "bp_paper_fallback": "yes", "bp_sensitive_data": ["none"], "bp_it_owner": "staff",
            "bp_device_count": "3_5", "bp_cyber_insurance": "yes",
            "iam_shared_logins": "no", "iam_former_staff_access": "no", "iam_mfa_email": "yes",
            "iam_mfa_banking": "yes", "iam_mfa_pos_admin": "yes", "iam_admin_count": "one",
            "iam_password_manager": "yes", "iam_phished_before": "no", "iam_payment_verification": "yes",
            "iam_unique_passwords": "yes", "iam_account_list": "yes", "iam_security_training": "yes",
            "net_guest_wifi_separate": "yes", "net_router_default_password": "no", "net_router_admin_logged_in": "yes",
            "net_router_updated": "last_year", "net_remote_access_used": "no", "net_dns_filtering": "yes",
            "pat_auto_updates": "yes", "pat_old_os": "no", "pat_pos_supported": "yes",
            "pat_update_reminder_month": "no", "pat_browser_updates": "yes", "pat_software_list": "yes",
            "end_antivirus": "yes", "end_encryption": "yes", "end_screen_lock": "yes",
            "end_personal_phones_email": "yes", "end_old_devices": "no", "end_device_list": "yes",
            "bkp_backed_up": "yes", "bkp_locations": ["cloud", "offsite"], "bkp_restore_tested": "yes",
            "bkp_recovery_time": "hours", "bkp_contact_list": "yes", "bkp_incident_owner": "yes", "bkp_vendor_list": "yes",
            "bp_biometrics": "no", "bp_email_domain": "northsidepantry.example", "iam_breach_check": "yes",
        },
        "uploads": {
            "users_permissions": [
                {"user_id": "it-admin", "account_type": "admin", "is_admin": "Y", "mfa_enabled": "Y", "status": "active",
                 "created_date": "2022-01-10", "last_login_date": d(12), "role_or_department": "Board treasurer (admin account)"},
                *[
                    {"user_id": f"volunteer-{i}", "account_type": "staff", "is_admin": "N", "mfa_enabled": "Y", "status": "active",
                     "created_date": created(0.5, 3), "last_login_date": jitter(2, 10), "role_or_department": "Volunteer coordinator"}
                    for i in range(1, 6)
                ],
                {"user_id": "former-volunteer", "account_type": "staff", "is_admin": "N", "mfa_enabled": "Y", "status": "disabled",
                 "created_date": "2023-03-01", "last_login_date": d(300), "role_or_department": "Volunteer"},
            ],
            "firewall_rules": [
                {"rule_id": "1", "enabled": "Y", "action": "allow", "direction": "outbound", "source": "lan", "destination": "any", "service_or_port": "any", "comment": "Default outbound"},
                {"rule_id": "2", "enabled": "Y", "action": "allow", "direction": "outbound", "source": "guest", "destination": "wan", "service_or_port": "80,443,53", "comment": "Guest internet only"},
                {"rule_id": "3", "enabled": "Y", "action": "deny", "direction": "inbound", "source": "any", "destination": "any", "service_or_port": "any", "comment": "Default deny"},
            ],
            "patch_inventory": [
                {"device_id": "office-laptop-1", "device_type": "laptop", "os_name": "Windows", "os_version": "11 25H2 (W)",
                 "auto_update_enabled": "Y", "last_patch_date": d(21), "pending_critical_updates": 0,
                 "key_software_name": "Microsoft 365 Apps", "key_software_version": "Current Channel", "vendor_supported": "Y"},
                {"device_id": "office-laptop-2", "device_type": "laptop", "os_name": "macOS", "os_version": "15",
                 "auto_update_enabled": "Y", "last_patch_date": d(15), "pending_critical_updates": 0,
                 "key_software_name": "Microsoft 365 Apps", "key_software_version": "Current Channel", "vendor_supported": "Y"},
            ],
            "endpoint_protection": [
                {"device_id": "office-laptop-1", "device_type": "laptop", "protection_product": "Microsoft Defender Antivirus", "protection_enabled": "Y",
                 "definitions_date": d(0), "disk_encryption": "Y", "screen_lock": "Y", "last_seen_date": d(0)},
                {"device_id": "office-laptop-2", "device_type": "laptop", "protection_product": "Microsoft Defender for Endpoint (macOS)", "protection_enabled": "Y",
                 "definitions_date": d(1), "disk_encryption": "Y", "screen_lock": "Y", "last_seen_date": d(2)},
            ],
            "backup_jobs": [
                {"job_id": "1", "source_system": "sharepoint and onedrive", "destination_type": "cloud", "schedule": "daily",
                 "last_success_date": d(0), "last_restore_test_date": d(40), "encrypted": "Y", "retention_days": 90},
                {"job_id": "2", "source_system": "donor database export", "destination_type": "offline", "schedule": "weekly",
                 "last_success_date": d(3), "last_restore_test_date": d(40), "encrypted": "Y", "retention_days": 365},
            ],
        },
        "lookups": {"email_domain_check": [{"domain": "northsidepantry.example", "mx_provider": "microsoft", "spf_present": "Y", "spf_all_qualifier": "-all", "dmarc_present": "Y", "dmarc_policy": "reject", "dmarc_rua_present": "Y", "dkim_found": "Y", "checked_on": AS_OF.isoformat()}]},
        "expected_legal_flags": [],
        "expected": ["END-004"],
    }


BUSINESSES = [taqueria, daycare, salon, pantry]


def write_business(b: dict, out: Path = OUT) -> None:
    folder = out / b["slug"]
    (folder / "uploads").mkdir(parents=True, exist_ok=True)
    meta = {"as_of": AS_OF.isoformat(), "seed": SEED, **b["profile"]}
    (folder / "profile.yaml").write_text(yaml.safe_dump(meta, sort_keys=False, allow_unicode=True), encoding="utf-8")
    (folder / "answers.yaml").write_text(yaml.safe_dump(b["answers"], sort_keys=False), encoding="utf-8")
    for table, rows in b.get("lookups", {}).items():
        (folder / "lookups").mkdir(exist_ok=True)
        with (folder / "lookups" / f"{table}.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=TEMPLATE_FIELDS[table])
            w.writeheader()
            w.writerows(rows)
    for table, rows in b["uploads"].items():
        with (folder / "uploads" / f"{table}.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=TEMPLATE_FIELDS[table])
            w.writeheader()
            w.writerows(rows)
    expected = {
        "as_of": AS_OF.isoformat(),
        "labelled_by": "Hand-labelled from the Week 1 rule specs (rules/*.yaml), independent of engine output",
        "expected_rule_ids": sorted(b["expected"]),
        "expected_legal_flags": sorted(b.get("expected_legal_flags", [])),
    }
    (folder / "expected_findings.yaml").write_text(yaml.safe_dump(expected, sort_keys=False), encoding="utf-8")
    print(f"wrote {folder}  ({len(b['expected'])} expected findings)")


def main(out: Path = OUT) -> None:
    """Regenerate every business. Re-seeds so repeated calls give identical output."""
    Faker.seed(SEED)
    rng.seed(SEED)
    for factory in BUSINESSES:
        write_business(factory(), out)


if __name__ == "__main__":
    main()
