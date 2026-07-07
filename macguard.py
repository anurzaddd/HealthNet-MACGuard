import subprocess
import re
import platform
import json
from datetime import datetime

# ==============================================
# دیتابیس اختصاصی تجهیزات پزشکی (پیشوند MAC + رمزهای پیش‌فرض)
# ==============================================
VENDOR_DB = {
    "00:11:22": {"vendor": "GE Healthcare", "defaults": ["root:GE123", "admin:password", "ge:ge"]},
    "00:1B:24": {"vendor": "Siemens Medical", "defaults": ["administrator:siemens", "root:med", "sysadmin:sys"]},
    "00:0A:45": {"vendor": "Philips Medical", "defaults": ["admin:philips", "operator:operator", "root:root"]},
    "00:14:22": {"vendor": "Medtronic", "defaults": ["admin:medtronic", "service:service"]},
    "00:18:9B": {"vendor": "Drager Medical", "defaults": ["admin:drager", "service:drager"]},
    "48:2C:A0": {"vendor": "Mindray", "defaults": ["admin:mindray", "root:mindray"]},
    "00:1E:8C": {"vendor": "Zoll Medical", "defaults": ["admin:zoll", "operator:zoll"]},
    "00:02:17": {"vendor": "Stryker", "defaults": ["admin:stryker", "service:stryker"]},
    "00:0D:60": {"vendor": "Radiometer", "defaults": ["admin:radiometer"]},
    "A4:4E:31": {"vendor": "Esaote", "defaults": ["admin:esaote"]},
    "00:80:77": {"vendor": "Siemens (Old)", "defaults": ["root:siemens"]},
    "00:04:27": {"vendor": "GE (Older)", "defaults": ["root:ge"]},
    "08:00:46": {"vendor": "HP/Agilent Medical", "defaults": ["admin:hp"]}
}

def get_arp_table():
    """دریافت جدول ARP از سیستم‌عامل (ویندوز/لینوکس)"""
    system = platform.system()
    devices = []
    try:
        if system == "Windows":
            output = subprocess.check_output(["arp", "-a"], text=True, encoding='cp850')
            # نمونه: 192.168.1.1          00-11-22-33-44-55     dynamic
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f-]{17})"
        else:  # لینوکس یا مک
            output = subprocess.check_output(["arp", "-n"], text=True)
            pattern = r"(\d+\.\d+\.\d+\.\d+).+([0-9A-Fa-f:]{17})"

        for line in output.splitlines():
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                mac_raw = match.group(2).replace("-", ":").lower()
                # استانداردسازی فرمت MAC
                mac = ":".join(mac_raw.split(":")[:6])
                if mac != "00:00:00:00:00:00":
                    devices.append({"ip": ip, "mac": mac})
        return devices
    except Exception as e:
        print(f"❌ خطا در خواندن جدول ARP: {e}")
        print("   (لطفاً اسکریپت را با دسترسی Administrator/root اجرا کنید)")
        return []

def generate_html_report(findings, filename="MACGuard_Report.html"):
    """گزارش HTML زیبا برای ارائه به مدیریت بیمارستان"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"""<html dir="rtl">
<head><meta charset="UTF-8"><title>گزارش امنیت تجهیزات پزشکی</title>
<style>
body{{font-family:Tahoma; background:#f4f6f9; padding:20px;}}
.container{{max-width:900px; margin:auto; background:#fff; border-radius:10px; padding:25px; box-shadow:0 0 15px #ccc;}}
h1{{color:#c0392b; border-bottom:3px solid #e74c3c; padding-bottom:10px;}}
.danger{{background:#fdecea; border-right:5px solid #e74c3c; padding:12px; margin:15px 0; border-radius:4px;}}
.success{{background:#eafaf1; border-right:5px solid #27ae60; padding:12px;}}
table{{width:100%; border-collapse:collapse; margin-top:20px;}}
th{{background:#2c3e50; color:#fff; padding:12px; text-align:right;}}
td{{border-bottom:1px solid #ddd; padding:12px;}}
.badge{{background:#e67e22; color:#fff; padding:3px 10px; border-radius:12px; font-size:12px;}}
</style></head>
<body>
<div class="container">
    <h1>🏥 گزارش ممیزی رمزهای پیش‌فرض تجهیزات پزشکی</h1>
    <p><strong>تاریخ اسکن:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>تعداد کل دستگاه‌های پزشکی شناسایی‌شده:</strong> {len(findings)}</p>
""")
        if findings:
            for item in findings:
                f.write(f"""
                <div class="danger">
                    <h3>⚠️ {item['vendor']}</h3>
                    <p><strong>آی‌پی:</strong> {item['ip']} | <strong>MAC:</strong> {item['mac']}</p>
                    <p><strong>🔑 رمزهای پیش‌فرض خطرناک (حتماً تغییر دهید):</strong></p>
                    <ul>
                """)
                for cred in item['defaults']:
                    f.write(f"<li><code>{cred}</code></li>")
                f.write("""
                    </ul>
                    <p style="color:#c0392b;">✅ راهکار: این رمزها را غیرفعال و با رمز قوی جایگزین کنید.</p>
                </div>
                """)
        else:
            f.write('<div class="success">✅ تبریک! هیچ دستگاه پزشکی با رمز پیش‌فرض خطرناک در شبکه یافت نشد.</div>')
        
        f.write("""
    <hr>
    <p style="color:#7f8c8d; font-size:12px;">این گزارش توسط ابزار HealthNet-MACGuard تولید شده است.</p>
</div>
</body></html>
""")
    print(f"✅ گزارش HTML با نام '{filename}' ذخیره شد.")

def main():
    print("\n" + "="*50)
    print("🛡️  HealthNet-MACGuard - شناسایی رمزهای پیش‌فرض تجهیزات پزشکی")
    print("="*50 + "\n")
    
    print("🔄 در حال بررسی جدول ARP شبکه...")
    devices = get_arp_table()
    
    if not devices:
        print("❌ دستگاهی یافت نشد. اطمینان حاصل کنید به شبکه متصل هستید.")
        return

    findings = []
    for device in devices:
        mac_prefix = device["mac"][:8]  # 8 کاراکتر اول (مثلاً 00:11:22)
        if mac_prefix in VENDOR_DB:
            info = VENDOR_DB[mac_prefix]
            print(f"\n🚨 ** دستگاه پزشکی پیدا شد **")
            print(f"   نام: {info['vendor']}")
            print(f"   IP: {device['ip']} | MAC: {device['mac']}")
            print(f"   ⚠️  رمزهای پیش‌فرض: {', '.join(info['defaults'])}")
            findings.append({
                "vendor": info['vendor'],
                "ip": device['ip'],
                "mac": device['mac'],
                "defaults": info['defaults']
            })

    if not findings:
        print("\n✅ دستگاه پزشکی با رمز پیش‌فرض شناسایی نشد (یا جدول ARP کامل نیست).")
    else:
        print(f"\n⚠️  تعداد {len(findings)} دستگاه با ریسک امنیتی بالا شناسایی شد!")
        generate_html_report(findings)

if __name__ == "__main__":
    main()
