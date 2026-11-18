# -*- coding: utf-8 -*-
"""Toggle App Cloner options via uiautomator dump + adb tap."""
import re
import subprocess
import sys
import time
from xml.etree import ElementTree as ET

SERIAL = "1A051FDF600A11"
DUMP = r"g:\LogaToolChangerV2\_uidump_now.xml"


def adb(*args, check=True):
    cmd = ["adb", "-s", SERIAL, *args]
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=check)


def dump():
    adb("shell", "uiautomator", "dump", "/sdcard/uidump.xml")
    adb("pull", "/sdcard/uidump.xml", DUMP)
    return ET.parse(DUMP).getroot()


def bounds(b):
    m = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", b or "")
    if not m:
        return None
    x1, y1, x2, y2 = map(int, m.groups())
    return x1, y1, x2, y2, (x1 + x2) // 2, (y1 + y2) // 2


def tap(x, y):
    adb("shell", "input", "tap", str(x), str(y))
    time.sleep(0.45)


def swipe_up():
    adb("shell", "input", "swipe", "540", "1950", "540", "700", "350")
    time.sleep(0.7)


def back():
    adb("shell", "input", "keyevent", "KEYCODE_BACK")
    time.sleep(0.7)


def nodes(root):
    out = []
    for n in root.iter("node"):
        b = bounds(n.attrib.get("bounds"))
        if not b:
            continue
        out.append(
            {
                "text": (n.attrib.get("text") or "").strip(),
                "desc": (n.attrib.get("content-desc") or "").strip(),
                "cls": (n.attrib.get("class") or "").split(".")[-1],
                "checked": n.attrib.get("checked") == "true",
                "enabled": n.attrib.get("enabled") != "false",
                "clickable": n.attrib.get("clickable") == "true",
                "b": b,
            }
        )
    return out


def find_text(items, *needles, exact=False):
    for it in items:
        t = it["text"]
        for n in needles:
            if exact:
                if t == n:
                    return it
            else:
                if n.lower() in t.lower():
                    return it
    return None


def find_switch_near(items, text_item):
    """Find Switch whose vertical center is near the text row."""
    _, y1, _, y2, _, cy = text_item["b"]
    best = None
    best_d = 9999
    for it in items:
        if it["cls"] != "Switch":
            continue
        sx1, sy1, sx2, sy2, sx, sy = it["b"]
        if abs(sy - cy) < 90 and sx > 700:
            d = abs(sy - cy)
            if d < best_d:
                best_d = d
                best = it
    return best


def ensure_on(items, *needles, label=None):
    it = find_text(items, *needles)
    if not it:
        return "missing"
    sw = find_switch_near(items, it)
    name = label or it["text"]
    if sw is None:
        # maybe preference opens dialog - tap the row
        tap(it["b"][4], it["b"][5])
        return "opened"
    if sw["checked"]:
        print(f"  OK already ON: {name}")
        return "already"
    tap(sw["b"][4], sw["b"][5])
    print(f"  TURNED ON: {name}")
    time.sleep(0.35)
    return "on"


def scroll_enable(targets, max_swipes=10):
    """targets: list of (needles_tuple_or_str, label)"""
    remaining = []
    for t in targets:
        if isinstance(t[0], str):
            remaining.append(((t[0],), t[1] if len(t) > 1 else t[0]))
        else:
            remaining.append((t[0], t[1] if len(t) > 1 else t[0][0]))

    done = set()
    for swipe_i in range(max_swipes + 1):
        root = dump()
        items = nodes(root)
        still = []
        for needles, label in remaining:
            if label in done:
                continue
            r = ensure_on(items, *needles, label=label)
            if r in ("on", "already"):
                done.add(label)
            elif r == "opened":
                # dialog - try enable first switch / confirm
                time.sleep(0.5)
                root2 = dump()
                items2 = nodes(root2)
                # Prefer enabling a main switch, or select first useful option
                handled = False
                for it in items2:
                    if it["cls"] == "Switch" and not it["checked"] and it["enabled"]:
                        tap(it["b"][4], it["b"][5])
                        print(f"  (dialog) switch ON for: {label}")
                        handled = True
                        time.sleep(0.3)
                        break
                # look for confirm / OK / Áp dụng / Lưu / Enable-like
                if not handled:
                    for kw in ("OK", "Đồng ý", "Áp dụng", "Lưu", "Xong", "Bật", "Enable", "On"):
                        btn = find_text(items2, kw, exact=True)
                        if btn:
                            tap(btn["b"][4], btn["b"][5])
                            handled = True
                            break
                # if list of modes, tap first non-Off option
                if not handled:
                    for it in items2:
                        t = it["text"]
                        if t and t not in ("", "Hủy", "Cancel") and "không" not in t.lower() and it["clickable"]:
                            # skip titles
                            if len(t) < 40 and it["b"][1] > 400:
                                tap(it["b"][4], it["b"][5])
                                print(f"  (dialog) picked: {t} for {label}")
                                handled = True
                                time.sleep(0.4)
                                break
                back()
                done.add(label)
                print(f"  OPENED/SET: {label}")
            else:
                still.append((needles, label))
        remaining = still
        if not remaining:
            break
        if swipe_i < max_swipes:
            swipe_up()
    for needles, label in remaining:
        print(f"  NOT FOUND: {label}")
    return done


def open_group(name_needles):
    root = dump()
    items = nodes(root)
    it = find_text(items, *name_needles)
    if not it:
        print(f"GROUP NOT FOUND: {name_needles}")
        return False
    tap(it["b"][4], it["b"][5])
    time.sleep(0.8)
    return True


def main():
    section = sys.argv[1] if len(sys.argv) > 1 else "all"

    if section in ("cloning", "all"):
        print("=== CLONING OPTIONS ===")
        if not open_group(("Tùy chọn nhân bản",)):
            return
        targets = [
            (("Tăng khả năng tương thích", "Increase compatibility"), "Increase compatibility"),
            (("Ẩn dịch vụ của Google Play", "Hide Google Play Services"), "Hide Google Play Services"),
            (("Giải pháp của Google Play Services", "Google Play Services"), "GPS workaround"),
            (("Giải pháp cho tên quy trình", "Process name"), "Process name workaround"),
            (("Kiểm tra cách giải quyết tên gói", "tên gói", "Package name"), "Package name check"),
            (("Giải pháp kiểm tra APK", "APK"), "APK check"),
            (("Giải pháp khắc phục kiểm tra sao chép", "sao chép", "Clone check"), "Clone check"),
            (("Không đóng", "No kill"), "No kill"),
            (("Thay đổi tham chiếu ứng dụng", "Change app references"), "Change app references"),
        ]
        scroll_enable(targets, max_swipes=8)
        back()
        time.sleep(0.5)

    if section in ("identity", "all"):
        print("=== IDENTITY OPTIONS ===")
        if not open_group(("Nhận dạng", "Identity")):
            return
        targets = [
            (("Ẩn thông tin Wi-Fi", "Hide Wi-Fi"), "Hide Wi-Fi info"),
            (("Ẩn SIM", "Hide SIM"), "Hide SIM & operator"),
            (("Ẩn máy chủ DNS", "Hide DNS"), "Hide DNS"),
            (("Ẩn thông tin CPU", "CPU / GPU", "Hide CPU"), "Hide CPU/GPU"),
            (("Đổi địa phương", "Change locale"), "Change locale"),
            (("Ngẫu nhiên hóa đường dẫn cài đặt", "installation path"), "Randomize install path"),
        ]
        scroll_enable(targets, max_swipes=10)
        back()
        time.sleep(0.5)

    if section in ("privacy", "all"):
        print("=== PRIVACY OPTIONS ===")
        if not open_group(("Tùy chọn bảo mật", "Privacy")):
            return
        targets = [
            (("Ẩn App Cloner", "Hide App Cloner"), "Hide App Cloner"),
            (("Ẩn ứng dụng khác", "Hide other apps"), "Hide other apps"),
            (("Ẩn ứng dụng nhân bản", "Hide cloned apps"), "Hide cloned apps"),
            (("Ẩn ứng dụng hệ thống", "Hide system apps"), "Hide system apps"),
            (("Ẩn tất cả ứng dụng đã cài", "Hide all installed"), "Hide all installed apps"),
            (("Ẩn chế độ nhà phát triển", "Hide developer"), "Hide developer mode"),
            (("Ẩn root", "Hide root"), "Hide root"),
            (("Vô hiệu hóa ghi nhật ký Logcat", "Disable Logcat", "Logcat"), "Disable Logcat"),
            (("Ẩn quyền truy cập", "Accessibility access"), "Accessibility access"),
            (("Tắt dịch vụ trợ năng", "Disable accessibility"), "Disable accessibility services"),
            (("Trạng thái sạc pin", "Battery charging"), "Battery charging state"),
        ]
        scroll_enable(targets, max_swipes=14)
        back()
        time.sleep(0.5)

    print("DONE section", section)


if __name__ == "__main__":
    main()
