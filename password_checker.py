#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Password GUI Checker (Arabic)
----------------------------
- تقييم قوة كلمة المرور (Entropy, grade, tips)
- مولد كلمة مرور قوية
- فحص مقابل ملف كلمات مسرَّبة محلي (plaintext أو SHA1)
- خيار اختياري للتحقق عبر Have I Been Pwned (k-anonymity)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import secrets, string, math, hashlib, threading, os

# Optional: requests only needed for HIBP online check
try:
    import requests
except Exception:
    requests = None

# -----------------------
# منطق التقييم والتوليد
# -----------------------
COMMON_WEAK_PATTERNS = {
    "password","123456","qwerty","letmein","admin","welcome","abc123","iloveyou",
    "1111","1234","0000","password1"
}

def estimate_entropy(password: str) -> float:
    pool_size = 0
    if any(c.islower() for c in password): pool_size += 26
    if any(c.isupper() for c in password): pool_size += 26
    if any(c.isdigit() for c in password): pool_size += 10
    if any(c in string.punctuation for c in password): pool_size += len(string.punctuation)
    if pool_size == 0: return 0.0
    return math.log2(pool_size) * len(password)

def grade_entropy(entropy: float) -> str:
    if entropy < 28: return "ضعيف"
    if entropy < 50: return "متوسط"
    return "قوي"

def analyze_password(password: str) -> dict:
    length = len(password)
    entropy = estimate_entropy(password)
    notes = []

    # طول
    if length < 8:
        notes.append("قصيرة جدًا — يُنصح بطول 12 حرفًا أو أكثر.")
    elif length < 12:
        notes.append("الطول مقبول لكن 12+ أفضل للحسابات الحساسة.")

    # تنوع
    types_count = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password)
    ])
    if types_count < 3:
        notes.append("ضعف في تنوع الأحرف — أضف أحرفًا كبيرة/أرقام/رموز.")

    # كلمات شائعة
    pl = password.lower()
    for w in COMMON_WEAK_PATTERNS:
        if w in pl:
            notes.append(f"تحتوي على نمط شائع: '{w}' — تجنبه.")

    # متتاليات بسيطة
    if password.isdigit() and (len(set(password)) <= 3):
        notes.append("سلسلة رقمية بسيطة (مثل 1111 أو 1234).")

    grade = grade_entropy(entropy)
    return {
        "password": password,
        "length": length,
        "entropy_bits": round(entropy, 2),
        "grade": grade,
        "notes": notes
    }

def generate_password(length=16, require_types=True):
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    while True:
        pw = ''.join(secrets.choice(alphabet) for _ in range(length))
        if not require_types:
            return pw
        if (any(c.islower() for c in pw)
            and any(c.isupper() for c in pw)
            and any(c.isdigit() for c in pw)
            and any(c in string.punctuation for c in pw)):
            return pw

# -----------------------
# فحص كلمة المرور مقابل ملف مسرَّب
# يدعم ملف نصي يحتوي كلمات (واحدة في كل سطر)
# أو ملف يحتوي SHA1 كل سطر (طول السطر 40 حرف hex)
# -----------------------
class BreachDB:
    def __init__(self):
        self.loaded = False
        self.is_sha1 = False
        self.set_data = set()
        self.source_path = None

    def load_file(self, path):
        # تحميل الملف في ذاكرة (قد يكون كبيرًا؛ استخدم بعناية)
        s = set()
        is_sha1 = None
        total = 0
        with open(path, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                if is_sha1 is None:
                    # تخمين: هل هذا ملف SHA1 ؟
                    if len(line) == 40 and all(c in "0123456789abcdefABCDEF" for c in line):
                        is_sha1 = True
                    else:
                        is_sha1 = False
                if is_sha1:
                    s.add(line.lower())
                else:
                    s.add(line)
        self.set_data = s
        self.is_sha1 = bool(is_sha1)
        self.loaded = True
        self.source_path = path
        return {"count": total, "is_sha1": self.is_sha1}

    def check_password(self, password: str) -> bool:
        if not self.loaded:
            raise RuntimeError("Breach DB not loaded")
        if self.is_sha1:
            h = hashlib.sha1(password.encode("utf-8")).hexdigest().lower()
            return h in self.set_data
        else:
            return password in self.set_data

# -----------------------
# HIBP online check (k-anonymity) — اختياري
# يعتمد على requests؛ إذا لم تتوافر المكتبة يُعطى تحذير
# -----------------------
def hibp_check(password: str) -> int:
    """
    Returns the number of times the password was seen according to HIBP,
    or -1 if cannot check (no requests available or error).
    """
    if requests is None:
        return -1
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        resp = requests.get(url, timeout=8)
        if resp.status_code != 200:
            return -1
        data = resp.text.splitlines()
        for line in data:
            parts = line.split(":")
            if len(parts) != 2: continue
            if parts[0].strip().upper() == suffix:
                return int(parts[1].strip())
        return 0
    except Exception:
        return -1

# -----------------------
# واجهة المستخدم (Tkinter)
# -----------------------
class PasswordApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("مقيّم قوة كلمة المرور — عربي")
        self.geometry("760x520")
        self.resizable(False, False)

        self.breach_db = BreachDB()

        self._build_ui()

    def _build_ui(self):
        pad = 10
        frm = ttk.Frame(self, padding=pad)
        frm.pack(fill="both", expand=True)

        # قسم إدخال وكشف
        left = ttk.Frame(frm)
        left.pack(side="left", fill="both", expand=True, padx=(0,8))

        ttk.Label(left, text="أدخل كلمة المرور:", font=("TkDefaultFont", 11, "bold")).pack(anchor="w")
        self.pw_var = tk.StringVar()
        pw_entry = ttk.Entry(left, textvariable=self.pw_var, show="*", width=36)
        pw_entry.pack(anchor="w", pady=(6,8))

        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="إظهار النص", variable=self.show_var, command=self._toggle_show).pack(anchor="w")

        # أزرار الإجراءات
        btn_frame = ttk.Frame(left)
        btn_frame.pack(anchor="w", pady=(10,6))
        ttk.Button(btn_frame, text="تقييم", command=self.on_evaluate).grid(row=0,column=0,padx=6)
        ttk.Button(btn_frame, text="توليد كلمة قوية", command=self.on_generate).grid(row=0,column=1,padx=6)
        ttk.Button(btn_frame, text="نسخ إلى الحافظة", command=self.copy_to_clipboard).grid(row=0,column=2,padx=6)

        # منطقة النتائج
        res_frame = ttk.LabelFrame(left, text="النتيجة")
        res_frame.pack(fill="x", pady=(12,6))
        self.grade_lbl = ttk.Label(res_frame, text="النتيجة: -", font=("TkDefaultFont", 12, "bold"))
        self.grade_lbl.pack(anchor="w", padx=8, pady=6)
        self.details_text = tk.Text(res_frame, height=8, wrap="word")
        self.details_text.pack(fill="both", padx=8, pady=(0,8))

        # خيار فحص محلي للقاعدة المخترقة
        breach_frame = ttk.LabelFrame(left, text="قائمة كلمات مسرَّبة (محلي)")
        breach_frame.pack(fill="x", pady=(6,0))
        ttk.Label(breach_frame, text="ملف القوائم (نص أو SHA1)").pack(anchor="w", padx=8, pady=6)
        bframe = ttk.Frame(breach_frame)
        bframe.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(bframe, text="تحميل ملف", command=self.load_breach_file).pack(side="left")
        self.breach_status_lbl = ttk.Label(bframe, text="لم يتم التحميل", foreground="gray")
        self.breach_status_lbl.pack(side="left", padx=8)

        # يمين: إعدادات ومولد سريع
        right = ttk.Frame(frm, width=280)
        right.pack(side="left", fill="y")

        # مولد سريع
        ttk.Label(right, text="مولد كلمة مرور", font=("TkDefaultFont", 11, "bold")).pack(anchor="w")
        gen_frame = ttk.Frame(right)
        gen_frame.pack(fill="x", pady=(6,8))
        ttk.Label(gen_frame, text="الطول:").grid(row=0,column=0, sticky="w")
        self.gen_len = tk.IntVar(value=16)
        ttk.Spinbox(gen_frame, from_=6, to=64, textvariable=self.gen_len, width=6).grid(row=0,column=1, sticky="w", padx=6)
        self.require_types_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(gen_frame, text="ضمان تنوّع الأنواع", variable=self.require_types_var).grid(row=1,column=0, columnspan=2, sticky="w", pady=(6,0))
        ttk.Button(gen_frame, text="توليد ووضع في الحقل", command=self.on_generate).grid(row=2,column=0, columnspan=2, pady=(8,0))

        # HIBP اختيارى
        ttk.Label(right, text="فحص عبر Have I Been Pwned (اختياري)", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(12,4))
        ttk.Label(right, text="(يتطلب مكتبة requests واتصال إنترنت)").pack(anchor="w")
        hibp_btn = ttk.Button(right, text="تحقق الآن (HIBP)", command=self.on_hibp_check)
        hibp_btn.pack(anchor="w", pady=(8,4))

        # ملحوظات إضافية
        notes = ("نصائح: استخدم مدير كلمات مرور، فعّل المصادقة الثنائية، "
                 "وتجنّب إعادة استخدام نفس الكلمة في خدمات متعددة.")
        ttk.Label(right, text=notes, wraplength=240, foreground="gray").pack(anchor="w", pady=(18,0))

        # حالة أسفل الواجهة
        self.status = ttk.Label(self, text="جاهز", relief="sunken", anchor="w")
        self.status.pack(side="bottom", fill="x")

    # UI helpers
    def _toggle_show(self):
        show = "" if self.show_var.get() else "*"
        for w in self.winfo_children():
            pass
        # find entry widget and toggle - simple direct approach:
        for child in self.winfo_children():
            for sub in child.winfo_children():
                if isinstance(sub, ttk.Entry):
                    sub.config(show=show)
                    return

    def set_status(self, text):
        self.status.config(text=text)

    # أزرار الأحداث
    def on_evaluate(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showinfo("تنبيه", "أدخل كلمة مرور أولاً")
            return
        res = analyze_password(pw)
        self.grade_lbl.config(text=f"النتيجة: {res['grade']}  —  إنتروبيا: {res['entropy_bits']} bits")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("end", f"الطول: {res['length']}\\n")
        if res['notes']:
            self.details_text.insert("end", "\\nملاحظات لتحسين الأمان:\\n")
            for n in res['notes']:
                self.details_text.insert("end", " - " + n + "\\n")
        else:
            self.details_text.insert("end", "\\nلا توجد ملاحظات — تبدو كلمة المرور جيدة.\\n")

        # فحص محلي إن كانت القاعدة محمّلة
        if self.breach_db.loaded:
            try:
                found = self.breach_db.check_password(pw)
                if found:
                    self.details_text.insert("end", "\\n⚠️ هذه الكلمة موجودة في قاعدة كلمات مسرَّبة محليًا!\\n")
                else:
                    self.details_text.insert("end", "\\n✔️ لم تُعثر الكلمة في قاعدة القوائم المحلّية.\\n")
            except Exception as e:
                self.details_text.insert("end", f"خطأ في فحص القاعدة: {e}\\n")

    def on_generate(self):
        L = max(6, int(self.gen_len.get()))
        pw = generate_password(L, require_types=self.require_types_var.get())
        self.pw_var.set(pw)
        self.set_status("تم التوليد ووضع الكلمة في الحقل")
        self.on_evaluate()

    def copy_to_clipboard(self):
        pw = self.pw_var.get()
        if not pw:
            return
        self.clipboard_clear()
        self.clipboard_append(pw)
        self.set_status("نسخ إلى الحافظة")

    def load_breach_file(self):
        path = filedialog.askopenfilename(title="اختر ملف كلمات مسرَّبة", filetypes=[("Text files","*.txt;*.lst;*.csv"),("All files","*.*")])
        if not path:
            return
        self.set_status("جارٍ التحميل...")
        def worker():
            try:
                info = self.breach_db.load_file(path)
                typ = "SHA1" if info["is_sha1"] else "plaintext"
                self.breach_status_lbl.config(text=f"محمل: {os.path.basename(path)} ({typ}, {info['count']} سطر)") 
                self.set_status("تم تحميل قاعدة القوائم")
            except Exception as e:
                messagebox.showerror("خطأ", f"فشل تحميل الملف: {e}")
                self.set_status("خطأ في التحميل")
        threading.Thread(target=worker, daemon=True).start()

    def on_hibp_check(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showinfo("تنبيه", "أدخل كلمة مرور أولاً")
            return
        if requests is None:
            messagebox.showwarning("مفقود", "مكتبة requests غير متاحة. ثبّتها: pip install requests")
            return
        self.set_status("جارٍ فحص HIBP...")
        def worker():
            try:
                count = hibp_check(pw)
                if count == -1:
                    msg = "تعذّر الاتصال بخدمة HIBP أو حدث خطأ."
                elif count == 0:
                    msg = "لم تُعثر HIBP على الكلمة (لم تُسجّل كمسرَّبة حسب الخدمة)."
                else:
                    msg = f"وجدت HIBP الكلمة {count} مرة(s) في قواعد البيانات المسربة — يُنصح بتغييرها فورًا."
                messagebox.showinfo("نتيجة HIBP", msg)
            finally:
                self.set_status("جاهز")
        threading.Thread(target=worker, daemon=True).start()

# -----------------------
# تشغيل التطبيق
# -----------------------
def main():
    app = PasswordApp()
    app.mainloop()

if __name__ == "__main__":
    main()
