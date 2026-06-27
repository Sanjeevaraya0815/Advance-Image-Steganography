



#     # ═══════════════════════════════════════════
#     # MODULE 7 — REPORT GENERATION
#     # ═══════════════════════════════════════════
#     elif section == "📄 Automated Report Generation":
#         st.header("Automated Report Generation")
#         st.info("Generate a PDF report summarising a steganography operation.")

#         with st.form("report_form"):
#             op_type = st.selectbox("Operation Type", ["Encode", "Decode", "Steganalysis", "Integrity Check"])
#             filename = st.text_input("Image Filename")
#             algorithm = st.text_input("Algorithm Used")
#             notes = st.text_area("Additional Notes")
#             image_hash = st.text_input("Image SHA-256 Hash (optional)")
#             submitted = st.form_submit_button("Generate PDF Report 📄")

#         if submitted:
#             report_data = {
#                 "Operation Type": op_type,
#                 "Image Filename": filename,
#                 "Algorithm": algorithm,
#                 "Image SHA-256": image_hash or "N/A",
#                 "Notes": notes,
#                 "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#             }
#             pdf_bytes = generate_report(report_data)
#             log_activity("Report Generated", f"Op: {op_type}, File: {filename}")
#             st.success("Report generated successfully!")
#             st.download_button("📥 Download PDF Report", pdf_bytes, "stego_report.pdf", "application/pdf")

#     # ═══════════════════════════════════════════
#     # MODULE 8 — ACTIVITY LOG
#     # ═══════════════════════════════════════════
#     elif section == "📋 Activity Log":
#         st.header("Activity Logging System")
#         logs = get_logs()
#         if logs:
#             st.success(f"{len(logs)} log entries found.")
#             col1, col2 = st.columns([3, 1])
#             with col2:
#                 if st.button("Clear All Logs"):
#                     if os.path.exists(LOG_FILE):
#                         os.remove(LOG_FILE)
#                     st.rerun()
#             for entry in reversed(logs):
#                 with st.expander(f"[{entry['timestamp']}] {entry['action']}"):
#                     st.write(entry["details"])
#         else:
#             st.info("No activity logged yet. Actions performed in other modules will appear here.")


# if __name__ == "__main__":
#     main()
import streamlit as st
from PIL import Image, ExifTags
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import numpy as np
import io
import json
import os
import datetime
import math
import struct
import zlib
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas as pdf_canvas


# ─────────────────────────────────────────────
# ACTIVITY LOGGING SYSTEM
# ─────────────────────────────────────────────
LOG_FILE = "activity_log.json"


def log_activity(action: str, details: str):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "action": action,
        "details": details,
    }
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except Exception:
            logs = []
    logs.append(entry)
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)


def get_logs():
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return []
    return []


# ─────────────────────────────────────────────
# AES CIPHER — PASSWORD-BASED ENCRYPTION
# ─────────────────────────────────────────────
class AESCipher:
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[: self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size :]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        padding_needed = self.block_size - len(plain_text) % self.block_size
        return plain_text + chr(padding_needed) * padding_needed

    @staticmethod
    def __unpad(plain_text):
        return plain_text[: -ord(plain_text[-1])]


# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────
def to_binary(data):
    if isinstance(data, str):
        return "".join([format(ord(char), "08b") for char in data])
    elif isinstance(data, (bytes, np.ndarray)):
        return [format(byte, "08b") for byte in data]
    elif isinstance(data, (int, np.uint8)):
        return format(data, "08b")
    else:
        raise TypeError("Unsupported input type")


# ─────────────────────────────────────────────
# PAYLOAD CAPACITY ESTIMATOR
# ─────────────────────────────────────────────
def estimate_capacity(image: Image.Image, algorithm: str = "LSB") -> dict:
    img = image.convert("RGB")
    w, h = img.size
    total_pixels = w * h
    if algorithm == "LSB":
        bits = total_pixels * 3 * 1
    elif algorithm == "2-bit LSB":
        bits = total_pixels * 3 * 2
    elif algorithm == "DCT":
        bits = (total_pixels // 64) * 1
    else:
        bits = total_pixels * 3 * 1
    bytes_capacity = bits // 8
    return {
        "pixels": total_pixels,
        "bits": bits,
        "bytes": bytes_capacity,
        "kb": round(bytes_capacity / 1024, 2),
        "algorithm": algorithm,
    }


# ─────────────────────────────────────────────
# FILE INTEGRITY VERIFICATION
# ─────────────────────────────────────────────
def compute_hash(data: bytes, method: str = "SHA-256") -> str:
    if method == "SHA-256":
        return hashlib.sha256(data).hexdigest()
    elif method == "MD5":
        return hashlib.md5(data).hexdigest()
    elif method == "SHA-512":
        return hashlib.sha512(data).hexdigest()
    return hashlib.sha256(data).hexdigest()


def verify_integrity(data: bytes, known_hash: str, method: str = "SHA-256") -> bool:
    return compute_hash(data, method) == known_hash.strip().lower()


# ─────────────────────────────────────────────
# METADATA-BASED STEGANOGRAPHY
# ─────────────────────────────────────────────
def embed_in_metadata(image: Image.Image, secret_text: str) -> Image.Image:
    img = image.copy()
    exif_bytes = img.info.get("exif", b"")
    encoded = b64encode(secret_text.encode()).decode()
    img.info["Comment"] = encoded
    return img


def extract_from_metadata(image: Image.Image) -> str:
    comment = image.info.get("Comment", "")
    if comment:
        try:
            return b64decode(comment.encode()).decode()
        except Exception:
            return comment
    return ""


def save_image_with_metadata(image: Image.Image, metadata_text: str) -> bytes:
    img = image.convert("RGB")
    buffer = io.BytesIO()
    encoded = b64encode(metadata_text.encode()).decode()
    img.save(buffer, format="PNG", pnginfo=build_png_metadata(encoded))
    return buffer.getvalue()


def build_png_metadata(text: str):
    try:
        from PIL.PngImagePlugin import PngInfo
        meta = PngInfo()
        meta.add_text("Comment", text)
        return meta
    except Exception:
        return None


# ─────────────────────────────────────────────
# MULTIPLE STEGANOGRAPHY ALGORITHMS
# ─────────────────────────────────────────────

# ── LSB (1-bit) ──────────────────────────────
def encode_message_lsb(image: Image.Image, message: str, aes_cipher: AESCipher) -> Image.Image:
    img = image.convert("RGB")
    encrypted_message = aes_cipher.encrypt(message) + "$$$"
    message_bin = to_binary(encrypted_message)
    width, height = img.size
    idx = 0

    for x in range(width):
        for y in range(height):
            if idx >= len(message_bin):
                return img
            r, g, b = img.getpixel((x, y))
            r = int(to_binary(r)[:-1] + message_bin[idx], 2)
            g = int(
                to_binary(g)[:-1]
                + (message_bin[idx + 1] if idx + 1 < len(message_bin) else "0"),
                2,
            )
            b = int(
                to_binary(b)[:-1]
                + (message_bin[idx + 2] if idx + 2 < len(message_bin) else "0"),
                2,
            )
            img.putpixel((x, y), (r, g, b))
            idx += 3
    return img


def decode_message_lsb(image: Image.Image, aes_cipher: AESCipher) -> str:
    img = image.convert("RGB")
    width, height = img.size
    bit_buffer = []
    decoded_chars = []

    for x in range(width):
        for y in range(height):
            r, g, b = img.getpixel((x, y))
            bit_buffer.append(to_binary(r)[-1])
            bit_buffer.append(to_binary(g)[-1])
            bit_buffer.append(to_binary(b)[-1])

            # Decode one char at a time as soon as 8 bits are ready
            while len(bit_buffer) >= 8:
                byte = "".join(bit_buffer[:8])
                bit_buffer = bit_buffer[8:]
                try:
                    char = chr(int(byte, 2))
                    decoded_chars.append(char)
                    # Early exit: check last 3 chars for end marker
                    if len(decoded_chars) >= 3 and decoded_chars[-3] == "$" and decoded_chars[-2] == "$" and decoded_chars[-1] == "$":
                        full_text = "".join(decoded_chars[:-3])
                        return aes_cipher.decrypt(full_text)
                except Exception:
                    decoded_chars.append("?")

    raise ValueError("Decoding failed: No valid message or incorrect decryption key.")


# ── 2-bit LSB ────────────────────────────────
def encode_message_2bit(image: Image.Image, message: str, aes_cipher: AESCipher) -> Image.Image:
    img = image.convert("RGB")
    encrypted_message = aes_cipher.encrypt(message) + "$$$"
    message_bin = to_binary(encrypted_message)
    width, height = img.size
    idx = 0

    for x in range(width):
        for y in range(height):
            if idx >= len(message_bin):
                return img
            r, g, b = img.getpixel((x, y))
            rb = to_binary(r)
            gb = to_binary(g)
            bb = to_binary(b)
            rb = rb[:-2] + (message_bin[idx] if idx < len(message_bin) else "0") + (message_bin[idx + 1] if idx + 1 < len(message_bin) else "0")
            gb = gb[:-2] + (message_bin[idx + 2] if idx + 2 < len(message_bin) else "0") + (message_bin[idx + 3] if idx + 3 < len(message_bin) else "0")
            bb = bb[:-2] + (message_bin[idx + 4] if idx + 4 < len(message_bin) else "0") + (message_bin[idx + 5] if idx + 5 < len(message_bin) else "0")
            img.putpixel((x, y), (int(rb, 2), int(gb, 2), int(bb, 2)))
            idx += 6
    return img


def decode_message_2bit(image: Image.Image, aes_cipher: AESCipher) -> str:
    img = image.convert("RGB")
    width, height = img.size
    bit_buffer = []
    decoded_chars = []

    for x in range(width):
        for y in range(height):
            r, g, b = img.getpixel((x, y))
            bit_buffer.extend(list(to_binary(r)[-2:]))
            bit_buffer.extend(list(to_binary(g)[-2:]))
            bit_buffer.extend(list(to_binary(b)[-2:]))

            while len(bit_buffer) >= 8:
                byte = "".join(bit_buffer[:8])
                bit_buffer = bit_buffer[8:]
                try:
                    char = chr(int(byte, 2))
                    decoded_chars.append(char)
                    if len(decoded_chars) >= 3 and decoded_chars[-3] == "$" and decoded_chars[-2] == "$" and decoded_chars[-1] == "$":
                        full_text = "".join(decoded_chars[:-3])
                        return aes_cipher.decrypt(full_text)
                except Exception:
                    decoded_chars.append("?")

    raise ValueError("Decoding failed: No valid message or incorrect decryption key.")


# ── Image-in-Image ────────────────────────────
def encode_image(cover_image: Image.Image, secret_image: Image.Image) -> Image.Image:
    cover_img = cover_image.convert("RGB")
    secret_img = secret_image.resize(cover_img.size).convert("RGB")
    cover_pixels = np.array(cover_img)
    secret_pixels = np.array(secret_img) // 16
    encoded_pixels = (cover_pixels & 240) | secret_pixels
    return Image.fromarray(encoded_pixels.astype("uint8"), "RGB")


def decode_image(encoded_image: Image.Image, secret_size: tuple) -> Image.Image:
    encoded_img = np.array(encoded_image)
    secret_pixels = (encoded_img & 15) * 16
    secret_img = Image.fromarray(secret_pixels.astype("uint8"), "RGB")
    return secret_img.resize(secret_size)


# ─────────────────────────────────────────────
# STEGANALYSIS DETECTION MODULE
# ─────────────────────────────────────────────
def run_steganalysis(image: Image.Image) -> dict:
    img = image.convert("RGB")
    pixels = np.array(img)

    lsb_plane = pixels & 1
    lsb_mean = float(np.mean(lsb_plane))
    lsb_std = float(np.std(lsb_plane))

    r, g, b = pixels[:, :, 0], pixels[:, :, 1], pixels[:, :, 2]
    hist_r = np.histogram(r, bins=256, range=(0, 256))[0]
    hist_g = np.histogram(g, bins=256, range=(0, 256))[0]
    hist_b = np.histogram(b, bins=256, range=(0, 256))[0]

    pair_diff_r = np.sum(np.abs(hist_r[::2] - hist_r[1::2]))
    pair_diff_g = np.sum(np.abs(hist_g[::2] - hist_g[1::2]))
    pair_diff_b = np.sum(np.abs(hist_b[::2] - hist_b[1::2]))
    rs_score = (pair_diff_r + pair_diff_g + pair_diff_b) / 3.0

    suspicion_score = 0
    notes = []

    if abs(lsb_mean - 0.5) < 0.02:
        suspicion_score += 40
        notes.append("LSB plane is suspiciously uniform (close to 0.5 mean) — suggests embedded data.")
    if lsb_std < 0.45:
        suspicion_score += 20
        notes.append("Low LSB standard deviation — possible structured bit pattern.")
    if rs_score < 500:
        suspicion_score += 30
        notes.append("RS analysis shows low histogram pair differences — potential LSB tampering.")

    if suspicion_score >= 70:
        verdict = "HIGH suspicion — image likely contains hidden data."
    elif suspicion_score >= 40:
        verdict = "MEDIUM suspicion — some anomalies detected."
    else:
        verdict = "LOW suspicion — image appears clean."
        notes.append("No strong steganographic signatures found.")

    return {
        "lsb_mean": round(lsb_mean, 4),
        "lsb_std": round(lsb_std, 4),
        "rs_score": round(rs_score, 2),
        "suspicion_score": suspicion_score,
        "verdict": verdict,
        "notes": notes,
    }


# ─────────────────────────────────────────────
# ANTI-FORENSICS TECHNIQUES
# ─────────────────────────────────────────────
def apply_anti_forensics(image: Image.Image, technique: str) -> Image.Image:
    img = np.array(image.convert("RGB"))

    if technique == "Noise Injection":
        noise = np.random.randint(-3, 4, img.shape, dtype=np.int16)
        img = np.clip(img.astype(np.int16) + noise, 0, 255).astype(np.uint8)

    elif technique == "Histogram Equalisation":
        from PIL import ImageOps
        r = Image.fromarray(img[:, :, 0])
        g = Image.fromarray(img[:, :, 1])
        b = Image.fromarray(img[:, :, 2])
        r = np.array(ImageOps.equalize(r))
        g = np.array(ImageOps.equalize(g))
        b = np.array(ImageOps.equalize(b))
        img = np.stack([r, g, b], axis=2).astype(np.uint8)

    elif technique == "JPEG Re-compression Simulation":
        buf = io.BytesIO()
        Image.fromarray(img).save(buf, format="JPEG", quality=85)
        buf.seek(0)
        img = np.array(Image.open(buf).convert("RGB"))

    elif technique == "Random Pixel Shuffle (Border)":
        h, w = img.shape[:2]
        for _ in range(200):
            x1, y1 = random.randint(0, w - 1), random.randint(0, 3)
            x2, y2 = random.randint(0, w - 1), random.randint(h - 4, h - 1)
            img[y1, x1], img[y2, x2] = img[y2, x2].copy(), img[y1, x1].copy()

    return Image.fromarray(img)


# ─────────────────────────────────────────────
# AI-BASED STEGANOGRAPHY (Simulated / Rule-based)
# ─────────────────────────────────────────────
def ai_adaptive_encode(image: Image.Image, message: str, aes_cipher: AESCipher) -> Image.Image:
    img = image.convert("RGB")
    pixels = np.array(img)
    encrypted_message = aes_cipher.encrypt(message) + "$$$"
    message_bin = to_binary(encrypted_message)
    msg_idx = 0
    result = pixels.copy()
    h, w = pixels.shape[:2]

    complexity_map = []
    for y in range(h):
        for x in range(w):
            if x + 1 < w and y + 1 < h:
                diff = int(np.mean(np.abs(pixels[y, x].astype(int) - pixels[y, x + 1].astype(int))))
                complexity_map.append((diff, x, y))
    complexity_map.sort(key=lambda t: -t[0])

    for _, x, y in complexity_map:
        if msg_idx >= len(message_bin):
            break
        r, g, b = result[y, x]
        r = int(to_binary(int(r))[:-1] + message_bin[msg_idx], 2)
        if msg_idx + 1 < len(message_bin):
            g = int(to_binary(int(g))[:-1] + message_bin[msg_idx + 1], 2)
        if msg_idx + 2 < len(message_bin):
            b = int(to_binary(int(b))[:-1] + message_bin[msg_idx + 2], 2)
        result[y, x] = [r, g, b]
        msg_idx += 3

    return Image.fromarray(result.astype("uint8"), "RGB")


def ai_adaptive_decode(image: Image.Image, aes_cipher: AESCipher) -> str:
    img = image.convert("RGB")
    pixels = np.array(img)
    h, w = pixels.shape[:2]

    complexity_map = []
    for y in range(h):
        for x in range(w):
            if x + 1 < w:
                diff = int(np.mean(np.abs(pixels[y, x].astype(int) - pixels[y, x + 1].astype(int))))
                complexity_map.append((diff, x, y))
    complexity_map.sort(key=lambda t: -t[0])

    bit_buffer = []
    decoded_chars = []

    for _, x, y in complexity_map:
        r, g, b = pixels[y, x]
        bit_buffer.append(to_binary(int(r))[-1])
        bit_buffer.append(to_binary(int(g))[-1])
        bit_buffer.append(to_binary(int(b))[-1])

        while len(bit_buffer) >= 8:
            byte = "".join(bit_buffer[:8])
            bit_buffer = bit_buffer[8:]
            try:
                char = chr(int(byte, 2))
                decoded_chars.append(char)
                if len(decoded_chars) >= 3 and decoded_chars[-3] == "$" and decoded_chars[-2] == "$" and decoded_chars[-1] == "$":
                    full_text = "".join(decoded_chars[:-3])
                    return aes_cipher.decrypt(full_text)
            except Exception:
                decoded_chars.append("?")

    raise ValueError("AI decode failed: no hidden message found.")


# ─────────────────────────────────────────────
# AUTOMATED REPORT GENERATION
# ─────────────────────────────────────────────
def generate_report(report_data: dict) -> bytes:
    buffer = io.BytesIO()
    c = pdf_canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, height - 60, "Steganography Operation Report")

    c.setFont("Helvetica", 10)
    c.drawString(50, height - 85, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y = height - 120
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Operation Summary")
    y -= 20
    c.setFont("Helvetica", 11)

    for key, value in report_data.items():
        if y < 80:
            c.showPage()
            y = height - 60
        c.drawString(60, y, f"{key}: {value}")
        y -= 18

    c.setFont("Helvetica-Oblique", 9)
    c.drawString(50, 40, "Generated by Advanced Image Steganography Tool")
    c.save()
    return buffer.getvalue()


# ─────────────────────────────────────────────
# SECURE IMAGE TRANSMISSION (Email)
# ─────────────────────────────────────────────
def send_image_via_email(
    sender: str,
    password: str,
    recipient: str,
    subject: str,
    body: str,
    image_bytes: bytes,
    filename: str = "encoded_image.png",
) -> bool:
    try:
        msg = MIMEMultipart()
        msg["From"] = sender
        msg["To"] = recipient
        msg["Subject"] = subject
        msg.attach(__import__("email.mime.text", fromlist=["MIMEText"]).MIMEText(body, "plain"))

        part = MIMEBase("application", "octet-stream")
        part.set_payload(image_bytes)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={filename}")
        msg.attach(part)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())
        return True
    except Exception as e:
        st.error(f"Email error: {e}")
        return False


# ─────────────────────────────────────────────
# MAIN STREAMLIT APP
# ─────────────────────────────────────────────
def main():
    st.set_page_config(
        page_title="Advanced Image Steganography",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # ── Dark / Light mode state ───────────────
    if "dark_mode" not in st.session_state:
        st.session_state.dark_mode = True  # default: dark

    # ── Full CSS themes ───────────────────────
    DARK_CSS = """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

    html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {
        background-color: #0d1117 !important;
        color: #e6edf3 !important;
        font-family: 'Inter', sans-serif !important;
    }
    [data-testid="stSidebar"] {
        background-color: #161b22 !important;
        border-right: 1px solid #30363d;
    }
    [data-testid="stSidebar"] * { color: #e6edf3 !important; }
    h1, h2, h3, h4 { color: #ff6b6b !important; font-family: 'Inter', sans-serif !important; }
    p, label, span, div { color: #e6edf3 !important; }
    .stButton > button {
        background: linear-gradient(135deg, #ff6b6b, #ee5a24) !important;
        color: white !important; border-radius: 10px !important;
        padding: 10px 22px !important; font-size: 15px !important;
        border: none !important; font-weight: 600 !important;
        transition: transform 0.15s ease, box-shadow 0.15s ease !important;
        box-shadow: 0 4px 15px rgba(255,107,107,0.3) !important;
    }
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(255,107,107,0.5) !important;
    }
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div {
        background-color: #21262d !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
        border-radius: 8px !important;
    }
    [data-testid="stMetricValue"] { color: #ff6b6b !important; font-weight: 700 !important; }
    [data-testid="stMetricLabel"] { color: #8b949e !important; }
    .stAlert, [data-testid="stNotification"] {
        background-color: #21262d !important;
        border-radius: 10px !important;
        border: 1px solid #30363d !important;
    }
    [data-testid="stExpander"] {
        background-color: #161b22 !important;
        border: 1px solid #30363d !important;
        border-radius: 10px !important;
    }
    .stTabs [data-baseweb="tab-list"] { background-color: #161b22 !important; border-radius: 10px; }
    .stTabs [data-baseweb="tab"] { color: #8b949e !important; }
    .stTabs [aria-selected="true"] { color: #ff6b6b !important; border-bottom: 2px solid #ff6b6b !important; }
    [data-testid="stFileUploader"],
    [data-testid="stFileUploaderDropzone"],
    [data-testid="stFileUploaderDropzoneInstructions"] {
        background-color: #21262d !important;
        border-radius: 10px !important;
    }
    [data-testid="stFileUploader"] {
        border: 2px dashed #484f58 !important;
    }
    [data-testid="stFileUploaderDropzoneInstructions"] span,
    [data-testid="stFileUploaderDropzoneInstructions"] small,
    [data-testid="stFileUploaderDropzoneInstructions"] p {
        color: #8b949e !important;
    }
    [data-testid="stFileUploaderDropzone"] svg { fill: #8b949e !important; }
    [data-testid="stFileUploaderDropzone"] button {
        background-color: #30363d !important;
        color: #e6edf3 !important;
        border: 1px solid #484f58 !important;
        border-radius: 6px !important;
    }
    .stRadio > div { color: #e6edf3 !important; }
    hr { border-color: #30363d !important; }
    code { background-color: #21262d !important; color: #79c0ff !important; border-radius: 6px !important; }
    .reportblock { background: #21262d !important; padding: 12px; border-radius: 8px; margin-bottom: 8px; border: 1px solid #30363d; }
    </style>
    """

    LIGHT_CSS = """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

    html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {
        background-color: #f5f7fa !important;
        color: #1a1a2e !important;
        font-family: 'Inter', sans-serif !important;
    }
    [data-testid="stSidebar"] {
        background-color: #ffffff !important;
        border-right: 1px solid #e0e0e0;
        box-shadow: 2px 0 10px rgba(0,0,0,0.05);
    }
    [data-testid="stSidebar"] * { color: #1a1a2e !important; }
    h1, h2, h3, h4 { color: #ff6347 !important; font-family: 'Inter', sans-serif !important; }
    p, label, span, div { color: #1a1a2e !important; }
    .stButton > button {
        background: linear-gradient(135deg, #ff6347, #e5533d) !important;
        color: white !important; border-radius: 10px !important;
        padding: 10px 22px !important; font-size: 15px !important;
        border: none !important; font-weight: 600 !important;
        transition: transform 0.15s ease, box-shadow 0.15s ease !important;
        box-shadow: 0 4px 15px rgba(255,99,71,0.25) !important;
    }
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(255,99,71,0.45) !important;
    }
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div {
        background-color: #ffffff !important;
        color: #1a1a2e !important;
        border: 1px solid #dde1e7 !important;
        border-radius: 8px !important;
    }
    [data-testid="stMetricValue"] { color: #ff6347 !important; font-weight: 700 !important; }
    [data-testid="stMetricLabel"] { color: #555 !important; }
    .stAlert, [data-testid="stNotification"] {
        background-color: #fff3f0 !important;
        border-radius: 10px !important;
        border: 1px solid #ffd6cc !important;
    }
    [data-testid="stExpander"] {
        background-color: #ffffff !important;
        border: 1px solid #e0e0e0 !important;
        border-radius: 10px !important;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }
    .stTabs [data-baseweb="tab-list"] { background-color: #ffffff !important; border-radius: 10px; }
    .stTabs [data-baseweb="tab"] { color: #666 !important; }
    .stTabs [aria-selected="true"] { color: #ff6347 !important; border-bottom: 2px solid #ff6347 !important; }
    [data-testid="stFileUploader"],
    [data-testid="stFileUploaderDropzone"],
    [data-testid="stFileUploaderDropzoneInstructions"] {
        background-color: #fff8f6 !important;
        border-radius: 10px !important;
    }
    [data-testid="stFileUploader"] {
        border: 2px dashed #ffb3a0 !important;
    }
    [data-testid="stFileUploaderDropzoneInstructions"] span,
    [data-testid="stFileUploaderDropzoneInstructions"] small,
    [data-testid="stFileUploaderDropzoneInstructions"] p {
        color: #888 !important;
    }
    [data-testid="stFileUploaderDropzone"] svg { fill: #ff9980 !important; }
    [data-testid="stFileUploaderDropzone"] button {
        background-color: #ffffff !important;
        color: #ff6347 !important;
        border: 1.5px solid #ff6347 !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
    }
    [data-testid="stFileUploaderDropzone"] button:hover {
        background-color: #ff6347 !important;
        color: #ffffff !important;
    }
    .stRadio > div { color: #1a1a2e !important; }
    hr { border-color: #e0e0e0 !important; }
    code { background-color: #fff3f0 !important; color: #c0392b !important; border-radius: 6px !important; }
    .reportblock { background: #fff3f0; padding: 12px; border-radius: 8px; margin-bottom: 8px; border: 1px solid #ffd6cc; }
    </style>
    """

    # Apply selected theme
    if st.session_state.dark_mode:
        st.markdown(DARK_CSS, unsafe_allow_html=True)
    else:
        st.markdown(LIGHT_CSS, unsafe_allow_html=True)

    st.title("🔐 Advanced Image Steganography Suite")
    st.caption("Hide data, verify integrity, detect stego, generate reports — all in one tool.")

    # ── Sidebar navigation ────────────────────
    st.sidebar.title("Navigation")

    # ── Theme Toggle ──────────────────────────
    st.sidebar.markdown("---")
    mode_label = "☀️ Switch to Light Mode" if st.session_state.dark_mode else "🌙 Switch to Dark Mode"
    if st.sidebar.button(mode_label, key="theme_toggle"):
        st.session_state.dark_mode = not st.session_state.dark_mode
        st.rerun()
    current_mode = "🌑 Dark Mode" if st.session_state.dark_mode else "🌕 Light Mode"
    st.sidebar.caption(f"Current: {current_mode}")
    st.sidebar.markdown("---")

    section = st.sidebar.radio(
        "Choose Module:",
        [
            "🖼️ Encode / Decode",
            "🔍 Steganalysis Detection",
            "📐 Payload Capacity Estimator",
            "🧾 File Integrity Verification",
            "🕵️ Anti-Forensics",
            "📧 Secure Image Transmission",
            "📄 Automated Report Generation",
            "📋 Activity Log",
        ],
    )

    # ═══════════════════════════════════════════
    # MODULE 1 — ENCODE / DECODE
    # ═══════════════════════════════════════════
    if section == "🖼️ Encode / Decode":
        st.header("Encode / Decode")

        algorithm = st.selectbox(
            "🔬 Steganography Algorithm:",
            ["LSB (1-bit)", "2-bit LSB", "Image-in-Image", "Metadata-Based", "AI-Adaptive (Complexity-Guided)"],
        )

        action = st.radio("🎯 Action:", ("Encode", "Decode"))

        if algorithm == "Image-in-Image":
            uploaded_cover = st.file_uploader("Upload Cover Image 📷", type=["png", "jpg", "jpeg"], key="cov")
            if action == "Encode":
                uploaded_secret = st.file_uploader("Upload Secret Image 🖼️", type=["png", "jpg", "jpeg"], key="sec")
                if st.button("Encode Image-in-Image"):
                    if uploaded_cover and uploaded_secret:
                        cover = Image.open(uploaded_cover)
                        secret = Image.open(uploaded_secret)
                        result_img = encode_image(cover, secret)
                        buf = io.BytesIO()
                        result_img.save(buf, format="PNG")
                        log_activity("Encode Image-in-Image", f"Cover: {uploaded_cover.name}, Secret: {uploaded_secret.name}")
                        st.success("Image encoded successfully!")
                        st.download_button("📥 Download Encoded Image", buf.getvalue(), "encoded_image.png", "image/png")
                    else:
                        st.error("Please upload both images.")
            else:
                size = st.slider("Decoded image size (px)", 50, 800, 300)
                if st.button("Decode Image-in-Image"):
                    if uploaded_cover:
                        enc = Image.open(uploaded_cover)
                        dec = decode_image(enc, (size, size))
                        st.image(dec, caption="Decoded Secret Image")
                        buf = io.BytesIO()
                        dec.save(buf, format="PNG")
                        log_activity("Decode Image-in-Image", f"File: {uploaded_cover.name}")
                        st.download_button("📥 Download Decoded Image", buf.getvalue(), "decoded_secret.png", "image/png")
                    else:
                        st.error("Please upload an encoded image.")

        elif algorithm == "Metadata-Based":
            st.info("Embeds secret text into PNG metadata (Comment field).")
            uploaded = st.file_uploader("Upload Image 📷", type=["png", "jpg", "jpeg"], key="meta_img")
            if action == "Encode":
                meta_text = st.text_area("Secret text to embed in metadata 📝")
                if st.button("Embed in Metadata"):
                    if uploaded and meta_text:
                        img = Image.open(uploaded)
                        out_bytes = save_image_with_metadata(img, meta_text)
                        log_activity("Metadata Encode", f"File: {uploaded.name}, Text length: {len(meta_text)}")
                        st.success("Text embedded in image metadata!")
                        st.download_button("📥 Download Image with Metadata", out_bytes, "meta_encoded.png", "image/png")
                    else:
                        st.error("Please upload an image and enter text.")
            else:
                if st.button("Extract from Metadata"):
                    if uploaded:
                        from PIL.PngImagePlugin import PngImageFile
                        buf = io.BytesIO(uploaded.read())
                        img = Image.open(buf)
                        text = extract_from_metadata(img)
                        log_activity("Metadata Decode", f"File: {uploaded.name}")
                        if text:
                            st.success("Extracted text:")
                            st.text_area("Metadata Content:", text)
                        else:
                            st.warning("No metadata-embedded text found.")
                    else:
                        st.error("Please upload an image.")

        else:
            uploaded = st.file_uploader("Upload Image 📷", type=["png", "jpg", "jpeg"], key="lsb_img")
            key = st.text_input("Encryption Key 🔑 (required)")

            if action == "Encode":
                message = st.text_area("Message to Hide 📝")
                if st.button("Encode Message"):
                    if uploaded and message and key:
                        img = Image.open(uploaded)
                        cipher = AESCipher(key)
                        if algorithm == "LSB (1-bit)":
                            result_img = encode_message_lsb(img, message, cipher)
                        elif algorithm == "2-bit LSB":
                            result_img = encode_message_2bit(img, message, cipher)
                        else:
                            result_img = ai_adaptive_encode(img, message, cipher)
                        buf = io.BytesIO()
                        result_img.save(buf, format="PNG")
                        log_activity(f"Encode [{algorithm}]", f"File: {uploaded.name}, Msg length: {len(message)}")
                        st.success("Message encoded successfully!")
                        hash_val = compute_hash(buf.getvalue())
                        st.info(f"SHA-256 of encoded image: `{hash_val}`")
                        st.download_button("📥 Download Encoded Image", buf.getvalue(), "encoded_image.png", "image/png")
                    else:
                        st.error("Please fill all fields.")

            else:
                if st.button("Decode Message"):
                    if uploaded and key:
                        img = Image.open(uploaded)
                        cipher = AESCipher(key)
                        try:
                            if algorithm == "LSB (1-bit)":
                                msg = decode_message_lsb(img, cipher)
                            elif algorithm == "2-bit LSB":
                                msg = decode_message_2bit(img, cipher)
                            else:
                                msg = ai_adaptive_decode(img, cipher)
                            log_activity(f"Decode [{algorithm}]", f"File: {uploaded.name}")
                            st.success("Message decoded!")
                            st.text_area("Decoded Message 📜:", msg)
                        except ValueError as e:
                            st.error(str(e))
                    else:
                        st.error("Please upload an image and enter the key.")

    # ═══════════════════════════════════════════
    # MODULE 2 — STEGANALYSIS
    # ═══════════════════════════════════════════
    elif section == "🔍 Steganalysis Detection":
        st.header("Steganalysis Detection Module")
        st.info("Analyse an image for signs of hidden steganographic content.")

        uploaded = st.file_uploader("Upload Image to Analyse 🔎", type=["png", "jpg", "jpeg"])
        if st.button("Run Steganalysis"):
            if uploaded:
                img = Image.open(uploaded)
                results = run_steganalysis(img)
                log_activity("Steganalysis", f"File: {uploaded.name}, Verdict: {results['verdict']}")
                st.subheader("Analysis Results")
                verdict_color = "red" if "HIGH" in results["verdict"] else ("orange" if "MEDIUM" in results["verdict"] else "green")
                st.markdown(f"<h3 style='color:{verdict_color}'>{results['verdict']}</h3>", unsafe_allow_html=True)
                col1, col2, col3 = st.columns(3)
                col1.metric("LSB Mean", results["lsb_mean"])
                col2.metric("LSB Std Dev", results["lsb_std"])
                col3.metric("RS Score", results["rs_score"])
                st.metric("Suspicion Score", f"{results['suspicion_score']} / 100")
                st.subheader("Diagnostic Notes")
                for note in results["notes"]:
                    st.write(f"• {note}")
            else:
                st.error("Please upload an image.")

    # ═══════════════════════════════════════════
    # MODULE 3 — PAYLOAD CAPACITY
    # ═══════════════════════════════════════════
    elif section == "📐 Payload Capacity Estimator":
        st.header("Payload Capacity Estimator")
        uploaded = st.file_uploader("Upload Image 📷", type=["png", "jpg", "jpeg"])
        algo = st.selectbox("Algorithm:", ["LSB", "2-bit LSB", "DCT"])
        if st.button("Estimate Capacity"):
            if uploaded:
                img = Image.open(uploaded)
                cap = estimate_capacity(img, algo)
                log_activity("Capacity Estimate", f"File: {uploaded.name}, Algo: {algo}")
                st.subheader("Capacity Results")
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Pixels", f"{cap['pixels']:,}")
                col2.metric("Available Bits", f"{cap['bits']:,}")
                col3.metric("Bytes", f"{cap['bytes']:,}")
                col4.metric("Kilobytes", f"{cap['kb']} KB")
                st.info(f"Using **{algo}** you can hide approximately **{cap['kb']} KB** of data in this image.")
            else:
                st.error("Please upload an image.")

    # ═══════════════════════════════════════════
    # MODULE 4 — FILE INTEGRITY
    # ═══════════════════════════════════════════
    elif section == "🧾 File Integrity Verification":
        st.header("File Integrity Verification")
        method = st.selectbox("Hash Algorithm:", ["SHA-256", "MD5", "SHA-512"])

        tab1, tab2 = st.tabs(["Compute Hash", "Verify Hash"])

        with tab1:
            uploaded = st.file_uploader("Upload File 📁", key="hash_compute")
            if st.button("Compute Hash"):
                if uploaded:
                    data = uploaded.read()
                    h = compute_hash(data, method)
                    log_activity("Hash Compute", f"File: {uploaded.name}, Method: {method}")
                    st.success(f"**{method} Hash:**")
                    st.code(h)
                else:
                    st.error("Upload a file.")

        with tab2:
            uploaded2 = st.file_uploader("Upload File to Verify 📁", key="hash_verify")
            known = st.text_input("Known / Expected Hash:")
            if st.button("Verify"):
                if uploaded2 and known:
                    data = uploaded2.read()
                    ok = verify_integrity(data, known, method)
                    log_activity("Hash Verify", f"File: {uploaded2.name}, Match: {ok}")
                    if ok:
                        st.success("✅ File integrity verified — hashes match!")
                    else:
                        st.error("❌ Integrity check FAILED — hashes do not match.")
                else:
                    st.error("Upload a file and enter the expected hash.")

    # ═══════════════════════════════════════════
    # MODULE 5 — ANTI-FORENSICS
    # ═══════════════════════════════════════════
    elif section == "🕵️ Anti-Forensics":
        st.header("Anti-Forensics Techniques")
        st.info("Apply post-processing to an encoded image to reduce detectable steganographic signatures.")

        uploaded = st.file_uploader("Upload (Encoded) Image 📷", type=["png", "jpg", "jpeg"])
        technique = st.selectbox(
            "Technique:",
            ["Noise Injection", "Histogram Equalisation", "JPEG Re-compression Simulation", "Random Pixel Shuffle (Border)"],
        )
        st.warning("⚠️ Anti-forensics modifies pixel values — apply BEFORE decoding is needed, or decoding may fail.")
        if st.button("Apply Anti-Forensics"):
            if uploaded:
                img = Image.open(uploaded)
                result = apply_anti_forensics(img, technique)
                buf = io.BytesIO()
                result.save(buf, format="PNG")
                log_activity("Anti-Forensics", f"File: {uploaded.name}, Technique: {technique}")
                st.success(f"Applied: {technique}")
                st.image(result, caption="Processed Image", use_column_width=True)
                st.download_button("📥 Download Processed Image", buf.getvalue(), "anti_forensics.png", "image/png")
            else:
                st.error("Please upload an image.")

    # ═══════════════════════════════════════════
    # MODULE 6 — SECURE TRANSMISSION
    # ═══════════════════════════════════════════
    elif section == "📧 Secure Image Transmission":
        st.header("Secure Image Transmission (Email)")
        st.info("Send an encoded image securely via email (Gmail SMTP). Use an App Password if 2FA is enabled.")

        uploaded = st.file_uploader("Upload Image to Send 📷", type=["png", "jpg", "jpeg"])
        sender = st.text_input("Your Gmail Address")
        app_password = st.text_input("Gmail App Password", type="password")
        recipient = st.text_input("Recipient Email Address")
        subject = st.text_input("Email Subject", value="Secure Encoded Image")
        body = st.text_area("Email Body", value="Please find the encoded image attached.")

        if st.button("Send Image via Email 📧"):
            if uploaded and sender and app_password and recipient:
                image_bytes = uploaded.read()
                ok = send_image_via_email(sender, app_password, recipient, subject, body, image_bytes, uploaded.name)
                if ok:
                    log_activity("Email Sent", f"From: {sender}, To: {recipient}, File: {uploaded.name}")
                    st.success(f"✅ Image sent successfully to {recipient}!")
            else:
                st.error("Please fill all required fields and upload an image.")

    # ═══════════════════════════════════════════
    # MODULE 7 — REPORT GENERATION
    # ═══════════════════════════════════════════
    elif section == "📄 Automated Report Generation":
        st.header("Automated Report Generation")
        st.info("Generate a PDF report summarising a steganography operation.")

        with st.form("report_form"):
            op_type = st.selectbox("Operation Type", ["Encode", "Decode", "Steganalysis", "Integrity Check"])
            filename = st.text_input("Image Filename")
            algorithm = st.text_input("Algorithm Used")
            notes = st.text_area("Additional Notes")
            image_hash = st.text_input("Image SHA-256 Hash (optional)")
            submitted = st.form_submit_button("Generate PDF Report 📄")

        if submitted:
            report_data = {
                "Operation Type": op_type,
                "Image Filename": filename,
                "Algorithm": algorithm,
                "Image SHA-256": image_hash or "N/A",
                "Notes": notes,
                "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            pdf_bytes = generate_report(report_data)
            log_activity("Report Generated", f"Op: {op_type}, File: {filename}")
            st.success("Report generated successfully!")
            st.download_button("📥 Download PDF Report", pdf_bytes, "stego_report.pdf", "application/pdf")

    # ═══════════════════════════════════════════
    # MODULE 8 — ACTIVITY LOG
    # ═══════════════════════════════════════════
    elif section == "📋 Activity Log":
        st.header("Activity Logging System")
        logs = get_logs()
        if logs:
            st.success(f"{len(logs)} log entries found.")
            col1, col2 = st.columns([3, 1])
            with col2:
                if st.button("Clear All Logs"):
                    if os.path.exists(LOG_FILE):
                        os.remove(LOG_FILE)
                    st.rerun()
            for entry in reversed(logs):
                with st.expander(f"[{entry['timestamp']}] {entry['action']}"):
                    st.write(entry["details"])
        else:
            st.info("No activity logged yet. Actions performed in other modules will appear here.")

    # ═══════════════════════════════════════════
    # FOOTER — TEAM DETAILS
    # ═══════════════════════════════════════════
    st.markdown("<br><br>", unsafe_allow_html=True)

    if st.session_state.dark_mode:
        footer_bg        = "#161b22"
        footer_border    = "#30363d"
        footer_text      = "#e6edf3"
        footer_sub       = "#8b949e"
        card_bg          = "#21262d"
        card_border      = "#30363d"
        accent           = "#ff6b6b"
        college_color    = "#79c0ff"
    else:
        footer_bg        = "#ffffff"
        footer_border    = "#e0e0e0"
        footer_text      = "#1a1a2e"
        footer_sub       = "#666666"
        card_bg          = "#fff8f6"
        card_border      = "#ffd6cc"
        accent           = "#ff6347"
        college_color    = "#1a1a2e"

    st.markdown(
        f"""
        <style>
        .footer-wrapper {{
            background: {footer_bg};
            border: 1px solid {footer_border};
            border-top: 3px solid {accent};
            border-radius: 16px;
            padding: 32px 36px 24px 36px;
            margin-top: 20px;
        }}
        .footer-college {{
            text-align: center;
            font-size: 20px;
            font-weight: 700;
            color: {college_color} !important;
            letter-spacing: 0.5px;
            margin-bottom: 6px;
        }}
        .footer-project {{
            text-align: center;
            font-size: 13px;
            color: {footer_sub} !important;
            margin-bottom: 24px;
        }}
        .footer-divider {{
            border: none;
            border-top: 1px solid {footer_border};
            margin: 16px 0 24px 0;
        }}
        .footer-team-label {{
            text-align: center;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: {accent} !important;
            margin-bottom: 16px;
        }}
        .footer-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-bottom: 24px;
        }}
        .footer-card {{
            background: {card_bg};
            border: 1px solid {card_border};
            border-radius: 10px;
            padding: 14px 16px;
            text-align: center;
            transition: transform 0.2s ease;
        }}
        .footer-card:hover {{ transform: translateY(-3px); }}
        .footer-roll {{
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 1px;
            color: {accent} !important;
            margin-bottom: 4px;
        }}
        .footer-name {{
            font-size: 14px;
            font-weight: 600;
            color: {footer_text} !important;
        }}
        .footer-copy {{
            text-align: center;
            font-size: 11px;
            color: {footer_sub} !important;
            margin-top: 8px;
        }}
        </style>

        <div class="footer-wrapper">
            <div class="footer-college">🎓 Vardhaman College of Engineering</div>
            <div class="footer-project">Advanced Image Steganography — Internship Project</div>
            <hr class="footer-divider"/>
            <div class="footer-team-label">👥 Project Team</div>
            <div class="footer-grid">
                <div class="footer-card">
                    <div class="footer-roll">ST#IS#9377</div>
                    <div class="footer-name">Mr. B Sanjeevaraya</div>
                </div>
                <div class="footer-card">
                    <div class="footer-roll">ST#IS#9375</div>
                    <div class="footer-name">Mr. Akulate Prasanth</div>
                </div>
                <div class="footer-card">
                    <div class="footer-roll">ST#IS#9371</div>
                    <div class="footer-name">Mr. Booma Manjunath</div>
                </div>
                <div class="footer-card">
                    <div class="footer-roll">ST#IS#9374</div>
                    <div class="footer-name">Mr. Varaha Nanda Kishore Savalapurapu</div>
                </div>
            </div>
            <div class="footer-copy">© 2024 Vardhaman College of Engineering · Dept. of CSE (AI&ML) · All rights reserved.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
