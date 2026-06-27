
# Advanced Image Steganography Suite
## Full Project Report

**College:** Vardhaman College of Engineering  
**Department:** Computer Science and Engineering (AI&ML)  
**Team Members:**
| Roll No | Name |
|---|---|
| ST#IS#9377 | Mr. B Sanjeevaraya |
| ST#IS#9375 | Mr. Akulate Prasanth |
| ST#IS#9371 | Mr. Booma Manjunath |
| ST#IS#9374 | Mr. Varaha Nanda Kishore Savalapurapu |

---

## 1. Introduction

### What is this project?
This project is a **web-based tool** that allows users to **hide secret messages or images inside ordinary-looking image files** — without anyone knowing that a secret is hidden inside.

It uses a technique called **Steganography**, combined with **encryption**, to make hidden communication safe and undetectable.

### Simple Analogy
> Imagine you write a secret note, then hide it inside a regular book. Anyone looking at the book sees just a normal book — they don't know a secret note is inside. That's exactly what this tool does — but with digital images.

---

## 2. Key Definitions

### 2.1 Steganography
**Definition:** The practice of hiding secret information inside a non-secret file (like an image, audio, or video) so that only the sender and receiver know the secret exists.

**Example:**
- You have a photo of a dog 🐶
- You hide the message `"Meet me at 5pm"` inside that photo
- Anyone who sees the photo thinks it's just a normal dog photo
- Only the person who knows the secret key can extract the hidden message

**Difference from Encryption:**
| Encryption | Steganography |
|---|---|
| Hides the *content* of a message | Hides the *existence* of a message |
| Message looks scrambled | Message is invisible — no one knows it exists |
| e.g., `xK92!@#pL` | e.g., a normal-looking photo |

---

### 2.2 Cover Image
**Definition:** The original normal image used to hide the secret message inside.

**Example:** A photo of your college campus — used as the "container" for your hidden message.

---

### 2.3 Stego Image
**Definition:** The output image after the secret message is hidden inside it. It looks exactly like the cover image to the human eye, but contains hidden data inside the pixels.

---

### 2.4 Pixel
**Definition:** The smallest unit of a digital image. Each pixel has 3 color values: **Red, Green, Blue (RGB)**, each ranging from 0 to 255.

**Example:** A 1000×1000 image has 10,00,000 pixels. Each pixel stores 3 numbers (R, G, B).

---

### 2.5 LSB (Least Significant Bit)
**Definition:** Every number is stored in binary (0s and 1s). The **rightmost bit** (LSB) has the **least effect on the value** — changing it barely changes the color.

**Example:**
```
Original Red value:  200  =  1 1 0 0 1 0 0 0
Change LSB to 1:     201  =  1 1 0 0 1 0 0 1
```
The color changes from 200 → 201 — **humans cannot see this difference!**  
This tiny change is used to store 1 bit of secret data per channel.

---

### 2.6 AES Encryption (Advanced Encryption Standard)
**Definition:** A method to **scramble data** using a secret key so that even if someone finds the hidden data, they cannot read it without the correct password.

**How it works (simple):**
```
Original Message:  "Hello Bro!"
After AES-256:     "xK9@!#pL2mQr..."  ← looks like garbage
```

**This project uses AES-256 CBC** — the strongest encryption standard, also used by banks and governments.

---

### 2.7 Steganalysis
**Definition:** The process of **detecting** whether an image contains hidden steganographic data — like a forensic investigation.

**Example:** A cybersecurity expert suspects a criminal sent hidden messages via images. They run steganalysis to find out.

---

### 2.8 Anti-Forensics
**Definition:** Techniques applied to a stego image to **erase traces** of steganography, making it harder for steganalysis tools to detect hidden data.

---

## 3. Algorithms Used

### 3.1 LSB (1-bit) Steganography

**How it works:**
1. Convert the secret message to binary (0s and 1s)
2. Go through each pixel of the image
3. Replace the **last bit** of R, G, B values with bits from the message
4. Save the image — it looks identical to the original

**Example:**
```
Message: "Hi"  →  Binary: 01001000 01101001

Pixel (200, 150, 100):
  R: 11001000  →  11001000  (LSB = 0) ✅ bit from message
  G: 10010110  →  10010111  (LSB = 1) ✅ bit from message
  B: 01100100  →  01100100  (LSB = 0) ✅ bit from message
```

**Capacity:**  
A 1000×1000 image can hide **~375 KB** of text using 1-bit LSB.

**Pros:** Very hard to detect visually  
**Cons:** Lower capacity, slightly detectable by analysis

---

### 3.2 2-bit LSB Steganography

**How it works:**  
Same as 1-bit LSB, but instead of replacing 1 bit, it replaces the **last 2 bits** of each channel.

**Example:**
```
R: 11001000  →  11001001  (last 2 bits replaced)
```

**Capacity:** Double of 1-bit LSB (~750 KB in a 1MP image)  
**Pros:** Higher capacity  
**Cons:** Slightly more detectable

---

### 3.3 Image-in-Image Steganography

**How it works:**  
Hides an **entire secret image** inside a cover image by storing only the **top 4 bits** of the secret image in the **bottom 4 bits** of the cover image.

**Example:**
```
Cover pixel R value:  11110000  (top 4 bits kept)
Secret pixel R value: 10100000  →  reduce to 1010 (top 4 bits)
Combined:             11111010  ← stored in cover image
```

**Use Case:** Hiding a secret document photo or confidential ID card inside a normal photo.

---

### 3.4 Metadata-Based Steganography

**How it works:**  
Hides text inside the **PNG file's metadata Comment field** — not in pixels at all.

**Example:**
```
Normal PNG file info: width=1920, height=1080, created=2024
After embedding:      Comment = "SGVsbG8gV29ybGQ=" (Base64 encoded secret)
```

**Pros:** Doesn't affect image quality at all  
**Cons:** Easily stripped by image editors or social media platforms  

---

### 3.5 AI-Adaptive (Complexity-Guided) Steganography

**How it works:**  
Instead of hiding data in all pixels equally, this algorithm:
1. **Analyses every pixel** to find high-complexity (texture/edge) regions
2. **Hides data preferentially in noisy/textured areas** — where changes are less noticeable
3. Smooth areas (like sky, solid walls) are left untouched

**Example:**
```
Image of a forest:
  - Tree leaves area  →  HIGH complexity  →  hide data here ✅
  - Sky area          →  LOW complexity   →  skip this area ✅
```

**Pros:** Smartest algorithm — hardest to detect  
**Cons:** Slightly slower due to complexity analysis  

---

## 4. Working Process (Step by Step)

### Encoding (Hiding a Message)

```
Step 1: User uploads a cover image (e.g., dog.png)
         ↓
Step 2: User types the secret message ("Meet at 5pm")
         ↓
Step 3: User enters an encryption key ("mykey123")
         ↓
Step 4: AES-256 encrypts the message
         "Meet at 5pm" → "xK9@!#pLmQ2r..."
         ↓
Step 5: Encrypted message converted to binary
         "xK9@..." → 01001000 11001010 ...
         ↓
Step 6: Binary bits embedded into image pixels (LSB method)
         ↓
Step 7: Stego image saved as PNG and downloaded
         → encoded_image.png (looks same as dog.png!)
```

### Decoding (Extracting a Message)

```
Step 1: User uploads the stego image (encoded_image.png)
         ↓
Step 2: User enters the same encryption key ("mykey123")
         ↓
Step 3: Tool reads LSB of each pixel → builds binary string
         ↓
Step 4: Binary → encrypted text
         ↓
Step 5: AES-256 decrypts using the key
         "xK9@!#pLmQ2r..." → "Meet at 5pm"
         ↓
Step 6: Original message displayed on screen ✅
```

> **Important:** Wrong key → garbage output or error. The message is completely safe!

---

## 5. Steganalysis Module — How Detection Works

### RS Analysis (Regular-Singular Analysis)
The tool analyses **histogram pair differences** in pixel values.

- **Normal image:** Histogram looks natural — gradual distributions
- **LSB-modified image:** Histogram shows **suspicious uniformity** in even/odd pairs

### LSB Plane Statistics
- Checks the **mean** of all LSB values
- If mean ≈ **0.5** → suspicious (random data was embedded)
- Natural images have slightly irregular LSB distributions

### Suspicion Score
```
Score 0–39   →  LOW    →  Image appears clean 🟢
Score 40–69  →  MEDIUM →  Some anomalies detected 🟡
Score 70–100 →  HIGH   →  Image likely contains hidden data 🔴
```

---

## 6. Anti-Forensics Techniques

| Technique | What it does | Effect |
|---|---|---|
| **Noise Injection** | Adds tiny ±3 random noise to pixel values | Breaks steganalysis pattern |
| **Histogram Equalisation** | Redistributes pixel colour values evenly | Looks like photo editing |
| **JPEG Re-compression** | Simulates JPEG compression at 85% quality | Destroys LSB patterns |
| **Random Pixel Shuffle (Border)** | Randomly swaps 200 border pixels | Confuses forensic tools |

> ⚠️ Warning: Anti-forensics **destroys the hidden message**. Apply only if you no longer need to decode.

---

## 7. File Integrity Verification

### What is a Hash?
A hash is a **unique fingerprint** of a file, generated by a mathematical formula.  
Any tiny change in the file → completely different hash.

### Example (SHA-256)
```
Original file hash:   a3f8c2d1e4b7...
Tampered file hash:   9d12f4a8b3c2...   ← completely different!
```

### Supported Hash Algorithms
| Algorithm | Output Length | Speed | Security |
|---|---|---|---|
| MD5 | 128-bit (32 chars) | Fastest | Low (outdated) |
| SHA-256 | 256-bit (64 chars) | Fast | High ✅ |
| SHA-512 | 512-bit (128 chars) | Moderate | Highest ✅ |

### Use Case
> After sending a stego image via email, receiver computes SHA-256 hash and compares with sender's hash. If they match → image was not tampered in transit. ✅

---

## 8. Secure Image Transmission (Email)

### How it works
1. User encodes a secret message into an image
2. Enters Gmail credentials and recipient email
3. Tool sends the stego image as an **email attachment via Gmail SMTP SSL (Port 465)**
4. Recipient receives the image, uses the tool to decode it

### Security
- Uses **SSL encryption** for email transmission
- Supports **Gmail App Passwords** (2FA compatible)
- The image itself is AES-256 encrypted — even if email is intercepted, message is safe

---

## 9. Automated PDF Report Generation

After any operation, the tool can generate a **professional PDF report** containing:
- Operation type (Encode/Decode/Steganalysis)
- Image filename used
- Algorithm applied
- SHA-256 hash of the image
- Custom notes
- Timestamp of operation

**Use Case:** Documentation for academic submissions, security audits, or project demos.

---

## 10. Activity Log System

Every action performed in the tool is **automatically saved** to a JSON log file (`activity_log.json`) with:
- Timestamp
- Action type
- File name and details

**Example log entry:**
```json
{
  "timestamp": "2024-06-23T11:30:00",
  "action": "Encode [LSB (1-bit)]",
  "details": "File: dog.png, Msg length: 42"
}
```

**Use Case:** Audit trail for tracking all steganography operations — useful for project demonstrations and security reviews.

---

## 11. Real-World Use Cases

| Use Case | Who Uses It | How |
|---|---|---|
| **Covert Communication** | Military, Intelligence agencies | Send hidden messages inside public images |
| **Digital Watermarking** | Photographers, Media companies | Hide ownership info inside photos |
| **Copyright Protection** | Artists, Publishers | Embed invisible author info in images |
| **Forensic Investigation** | Cybersecurity experts | Detect hidden data in criminal evidence images |
| **Academic Research** | Students, Researchers | Study steganography and anti-forensics |
| **CTF Challenges** | Ethical hackers | Solve cybersecurity competition puzzles |
| **Secure Data Transfer** | Corporate | Transfer classified documents disguised as images |

---

## 12. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **User Interface** | Streamlit (Python) | Web app frontend |
| **Image Processing** | Pillow, NumPy | Pixel manipulation |
| **Encryption** | PyCryptodome (AES-256 CBC) | Secure message encryption |
| **PDF Generation** | ReportLab | Automated report creation |
| **Email Sending** | smtplib, MIME | Secure image transmission |
| **Hashing** | hashlib | File integrity verification |
| **Data Logging** | JSON | Activity audit trail |

---

## 13. System Architecture

```
┌────────────────────────────────────────────────────────┐
│                   Streamlit Web UI                      │
│   (Browser-based interface — runs on localhost:8501)    │
└────────────────────────────┬───────────────────────────┘
                             │
         ┌───────────────────▼──────────────────────┐
         │             Core Engine (new.py)          │
         │                                          │
         │  ┌──────────┐  ┌──────────┐  ┌────────┐ │
         │  │   AES    │  │   LSB    │  │  2-bit │ │
         │  │Encryption│  │Algorithm │  │  LSB   │ │
         │  └──────────┘  └──────────┘  └────────┘ │
         │  ┌──────────┐  ┌──────────┐  ┌────────┐ │
         │  │Image-in- │  │Metadata  │  │   AI   │ │
         │  │  Image   │  │  Based   │  │Adaptive│ │
         │  └──────────┘  └──────────┘  └────────┘ │
         │                                          │
         │  ┌──────────┐  ┌──────────┐  ┌────────┐ │
         │  │Stegana-  │  │  Anti-   │  │ Hash   │ │
         │  │  lysis   │  │Forensics │  │ Check  │ │
         │  └──────────┘  └──────────┘  └────────┘ │
         └──────────────────────────────────────────┘
                             │
              ┌──────────────┴─────────────┐
              │                            │
    ┌─────────▼──────────┐    ┌───────────▼──────────┐
    │   PIL / NumPy       │    │  activity_log.json   │
    │   (Image pixels)    │    │  (Audit trail)       │
    └────────────────────┘    └──────────────────────┘
```

---

## 14. Limitations

| Limitation | Explanation |
|---|---|
| **JPEG images** | JPEG compression destroys LSB data — always use PNG |
| **Image sharing apps** | WhatsApp/Instagram compress images, destroying hidden data |
| **Anti-forensics destroys data** | Once applied, cannot decode the message anymore |
| **AI-Adaptive is slow** | On large images, complexity map building takes time |
| **Email requires App Password** | Gmail 2FA users need to generate a special App Password |

---

## 15. Conclusion

The **Advanced Image Steganography Suite** is a comprehensive, all-in-one cybersecurity tool that demonstrates:

1. **Multiple steganography algorithms** — from basic LSB to AI-guided embedding
2. **Military-grade AES-256 encryption** — ensuring message safety even if detected
3. **Forensic detection** — steganalysis to find hidden data in suspicious images
4. **Anti-forensics** — techniques to erase steganographic signatures
5. **File integrity** — hash-based tamper detection
6. **Secure transmission** — encrypted email delivery
7. **Professional reporting** — PDF audit reports
8. **Full activity logging** — audit trail for every operation

This project successfully combines **information hiding**, **cryptography**, **digital forensics**, and **web application development** into a single, practical tool with real-world applications in cybersecurity and covert communication.

---

## 16. How to Use Each Module — Step by Step Guide

> **Before starting:** Run the app by executing `streamlit run new.py` in the terminal. Open your browser and go to **http://localhost:8501**

---

### Module 1 — 🖼️ Encode / Decode

This is the main module for hiding and retrieving secret messages.

---

#### 1A. Encode a Text Message (Hiding)

**Step 1:** Click **"🖼️ Encode / Decode"** in the left sidebar.

**Step 2:** Under **"Steganography Algorithm"**, select one of:
- `LSB (1-bit)` — safest, recommended for beginners
- `2-bit LSB` — more capacity
- `AI-Adaptive` — smartest, hardest to detect

**Step 3:** Under **"Action"**, select **"Encode"**.

**Step 4:** Click **"Upload Image 📷"** and select a `.png` image from your computer.
> ⚠️ Always use PNG format. JPEG will destroy the hidden data.

**Step 5:** In the **"Encryption Key 🔑"** field, type a password.
> Example: `mySecretKey123`  
> Remember this key — you will need it to decode later!

**Step 6:** In the **"Message to Hide 📝"** box, type your secret message.
> Example: `This is a confidential message for CSE AI&ML team.`

**Step 7:** Click the **"Encode Message"** button.

**Step 8:** A success message appears. You will also see the **SHA-256 hash** of the encoded image — save this for integrity verification.

**Step 9:** Click **"📥 Download Encoded Image"** to save the stego image to your computer.

✅ Done! The image now contains your hidden message.

---

#### 1B. Decode a Text Message (Retrieving)

**Step 1:** Click **"🖼️ Encode / Decode"** in the sidebar.

**Step 2:** Select the **same algorithm** used during encoding (e.g., `LSB (1-bit)`).

**Step 3:** Under **"Action"**, select **"Decode"**.

**Step 4:** Upload the **encoded image** (the stego image you downloaded earlier).

**Step 5:** Enter the **same encryption key** used during encoding.
> Example: `mySecretKey123`

**Step 6:** Click **"Decode Message"** button.

**Step 7:** Your original secret message appears in the text box on screen.

✅ Done! Message successfully retrieved.

> ❌ If wrong key is entered → Error message appears. No message is shown.

---

#### 1C. Image-in-Image (Hiding a Secret Image)

**Step 1:** Select algorithm → **"Image-in-Image"**, Action → **"Encode"**.

**Step 2:** Upload the **Cover Image** (the outer visible image).

**Step 3:** Upload the **Secret Image** (the image you want to hide inside).

**Step 4:** Click **"Encode Image-in-Image"** → Download the result.

**To Decode:**
- Select algorithm → **"Image-in-Image"**, Action → **"Decode"**
- Upload the encoded image
- Use the slider to set the decoded image size
- Click **"Decode Image-in-Image"** → Secret image appears

---

#### 1D. Metadata-Based Hiding

**Step 1:** Select algorithm → **"Metadata-Based"**, Action → **"Encode"**.

**Step 2:** Upload any `.png` image.

**Step 3:** Type secret text in the text area.

**Step 4:** Click **"Embed in Metadata"** → Download the image.

**To Decode:**
- Select **"Metadata-Based"**, Action → **"Decode"**
- Upload the metadata-encoded image
- Click **"Extract from Metadata"** → Text appears

---

### Module 2 — 🔍 Steganalysis Detection

Use this to check if an image has hidden content.

**Step 1:** Click **"🔍 Steganalysis Detection"** in the sidebar.

**Step 2:** Click **"Upload Image to Analyse 🔎"** and select any image.

**Step 3:** Click **"Run Steganalysis"** button.

**Step 4:** Read the results:
- **LSB Mean** — value near 0.5 = suspicious
- **LSB Std Dev** — very low = suspicious
- **RS Score** — very low = suspicious
- **Suspicion Score** — 0 to 100
- **Verdict** — LOW / MEDIUM / HIGH suspicion

> 🟢 LOW = Image is clean  
> 🟡 MEDIUM = Some anomalies found  
> 🔴 HIGH = Hidden data likely present

---

### Module 3 — 📐 Payload Capacity Estimator

Use this before encoding to check how much data an image can hold.

**Step 1:** Click **"📐 Payload Capacity Estimator"** in the sidebar.

**Step 2:** Upload your cover image.

**Step 3:** Select an algorithm from the dropdown:
- `LSB` — 1 bit per channel
- `2-bit LSB` — 2 bits per channel
- `DCT` — frequency domain estimation

**Step 4:** Click **"Estimate Capacity"**.

**Step 5:** Read the result:
- Total Pixels, Available Bits, Bytes, and **Kilobytes** shown as metric cards.

> 💡 If your message is larger than the capacity shown, choose a bigger image or a higher-capacity algorithm.

---

### Module 4 — 🧾 File Integrity Verification

Use this to generate or verify a file's hash fingerprint.

#### 4A. Compute Hash

**Step 1:** Click **"🧾 File Integrity Verification"** in the sidebar.

**Step 2:** Select hash method: `SHA-256`, `MD5`, or `SHA-512`.

**Step 3:** Go to **"Compute Hash"** tab.

**Step 4:** Upload any file (image, PDF, etc.).

**Step 5:** Click **"Compute Hash"** → Hash value is displayed as a code block.

**Step 6:** Copy and save this hash string.

---

#### 4B. Verify Hash

**Step 1:** Go to **"Verify Hash"** tab.

**Step 2:** Upload the file you want to verify.

**Step 3:** Paste the known/original hash in the text box.

**Step 4:** Click **"Verify"**.

- ✅ **Match** → File is original and untampered
- ❌ **No Match** → File was modified or corrupted

---

### Module 5 — 🕵️ Anti-Forensics

Use this to reduce detectable steganographic signatures in an encoded image.

> ⚠️ Warning: Apply ONLY when you no longer need to decode the message. Anti-forensics will destroy the hidden data!

**Step 1:** Click **"🕵️ Anti-Forensics"** in the sidebar.

**Step 2:** Upload the encoded (stego) image.

**Step 3:** Select a technique:

| Technique | Best Used When |
|---|---|
| `Noise Injection` | General purpose — safest option |
| `Histogram Equalisation` | Want to look like photo editing was done |
| `JPEG Re-compression Simulation` | Want JPEG-like artifacts added |
| `Random Pixel Shuffle (Border)` | Want to confuse border-based forensics |

**Step 4:** Click **"Apply Anti-Forensics"** → Processed image shown on screen.

**Step 5:** Click **"📥 Download Processed Image"** to save.

---

### Module 6 — 📧 Secure Image Transmission

Use this to directly email a stego image to a recipient.

**Step 1:** Click **"📧 Secure Image Transmission"** in the sidebar.

**Step 2:** Upload the encoded image you want to send.

**Step 3:** Fill in the form:
- **Your Gmail Address** → `yourname@gmail.com`
- **Gmail App Password** → Generate from Google Account → Security → App Passwords
- **Recipient Email** → `receiver@gmail.com`
- **Subject** → `Secure Encoded Image`
- **Body** → Your email message

**Step 4:** Click **"Send Image via Email 📧"**.

**Step 5:** Success message confirms email was sent.

> 💡 The recipient opens the image normally, then uses this tool to decode the hidden message.

---

### Module 7 — 📄 Automated Report Generation

Use this to generate a PDF report for any operation performed.

**Step 1:** Click **"📄 Automated Report Generation"** in the sidebar.

**Step 2:** Fill in the form:
- **Operation Type** → Select from: Encode / Decode / Steganalysis / Integrity Check
- **Image Filename** → Type the name of the image used
- **Algorithm Used** → Type the algorithm name (e.g., LSB 1-bit)
- **Additional Notes** → Add any extra information
- **Image SHA-256 Hash** → Paste the hash (optional)

**Step 3:** Click **"Generate PDF Report 📄"** button.

**Step 4:** Click **"📥 Download PDF Report"** → PDF saved to your computer.

> 💡 This PDF can be submitted as academic documentation or project proof.

---

### Module 8 — 📋 Activity Log

Use this to view a full history of all operations performed.

**Step 1:** Click **"📋 Activity Log"** in the sidebar.

**Step 2:** All previous actions are listed with:
- **Timestamp** — exact date and time
- **Action type** — e.g., Encode, Decode, Steganalysis
- **Details** — filename, algorithm, message length, etc.

**Step 3:** Click any entry to expand and see full details.

**Step 4:** To clear all logs, click the **"Clear All Logs"** button (top right).

---

### Quick Reference — Which Module to Use When?

| You Want To... | Use Module |
|---|---|
| Hide a secret text in an image | Module 1 → Encode |
| Retrieve a hidden text from image | Module 1 → Decode |
| Hide an image inside another image | Module 1 → Image-in-Image |
| Check if an image has hidden data | Module 2 → Steganalysis |
| Know how much data an image can hold | Module 3 → Capacity Estimator |
| Generate or verify a file hash | Module 4 → Integrity Verification |
| Remove steganographic traces | Module 5 → Anti-Forensics |
| Email the stego image securely | Module 6 → Secure Transmission |
| Create a PDF report of the operation | Module 7 → Report Generation |
| See history of all operations | Module 8 → Activity Log |

---

## 17. Conclusion

The **Advanced Image Steganography Suite** is a comprehensive, all-in-one cybersecurity tool that demonstrates:

1. **Multiple steganography algorithms** — from basic LSB to AI-guided embedding
2. **Military-grade AES-256 encryption** — ensuring message safety even if detected
3. **Forensic detection** — steganalysis to find hidden data in suspicious images
4. **Anti-forensics** — techniques to erase steganographic signatures
5. **File integrity** — hash-based tamper detection
6. **Secure transmission** — encrypted email delivery
7. **Professional reporting** — PDF audit reports
8. **Full activity logging** — audit trail for every operation

This project successfully combines **information hiding**, **cryptography**, **digital forensics**, and **web application development** into a single, practical tool with real-world applications in cybersecurity and covert communication.

---


