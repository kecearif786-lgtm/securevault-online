const enc = new TextEncoder();
const dec = new TextDecoder();

const hex = (buffer) =>
  Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");

function unhex(value) {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(value)) {
    throw new Error("Format data heksadesimal tidak valid.");
  }
  return new Uint8Array(value.match(/.{2}/g)?.map((part) => parseInt(part, 16)) || []);
}

async function derive(passphrase, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/* Skema tanda tangan Dissanayake dari prototipe awal.
   Hanya demonstrasi akademik, bukan implementasi kriptografi produksi. */
function modPow(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

function egcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x, y] = egcd(b, a % b);
  return [g, y, x - (a / b) * y];
}

function inv(a, modulus) {
  const [g, x] = egcd((a % modulus + modulus) % modulus, modulus);
  if (g !== 1n) throw new Error("Inverse tidak tersedia");
  return (x % modulus + modulus) % modulus;
}

function randomBig(bits) {
  const bytes = crypto.getRandomValues(new Uint8Array(bits / 8));
  bytes[0] |= 0xC0;
  bytes[bytes.length - 1] |= 1;
  return BigInt("0x" + hex(bytes));
}

function probablePrime(number) {
  if (number < 2n) return false;
  for (const prime of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n]) {
    if (number === prime) return true;
    if (number % prime === 0n) return false;
  }

  let d = number - 1n;
  let s = 0;
  while (d % 2n === 0n) {
    d /= 2n;
    s++;
  }

  for (let i = 0; i < 12; i++) {
    const a = BigInt(2 + Math.floor(Math.random() * 1000000));
    let x = modPow(a, d, number);
    if (x === 1n || x === number - 1n) continue;
    let passed = false;
    for (let j = 1; j < s; j++) {
      x = (x * x) % number;
      if (x === number - 1n) {
        passed = true;
        break;
      }
    }
    if (!passed) return false;
  }
  return true;
}

function prime(bits) {
  for (let i = 0; i < 100000; i++) {
    const candidate = randomBig(bits);
    if (probablePrime(candidate)) return candidate;
  }
  throw new Error("Gagal membuat kunci demo");
}

async function digestBig(message) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(message));
  return BigInt("0x" + hex(digest));
}

async function makeDemoKeys() {
  const p = prime(256);
  let q = prime(256);
  while (q === p) q = prime(256);
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const d = 65537n;
  const e = inv(d, phi);
  return { n: n.toString(), e: e.toString(), d: d.toString() };
}

async function signDemo(message, keys) {
  const messageHash = await digestBig(message);
  let r = 0n;
  while ((messageHash + r) % 4n !== 0n) r++;
  const a = messageHash + r - 2n;
  return {
    S: modPow(a, BigInt(keys.d), BigInt(keys.n)).toString(16),
    r: r.toString(),
    pub: { n: keys.n, e: keys.e }
  };
}

async function verifyDemo(message, signature) {
  try {
    const messageHash = await digestBig(message);
    const a = messageHash + BigInt(signature.r) - 2n;
    return modPow(
      BigInt("0x" + signature.S),
      BigInt(signature.pub.e),
      BigInt(signature.pub.n)
    ) === a;
  } catch (error) {
    console.error("Verifikasi tanda tangan demo gagal:", error);
    return false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // BAGIAN ENKRIPSI UNTUK HALAMAN compose.html
  const encryptBtn = document.getElementById("encryptBtn");
  if (encryptBtn) {
    encryptBtn.addEventListener("click", async () => {
      const message = document.getElementById("plain")?.value ?? "";
      const passphrase = document.getElementById("passphrase")?.value ?? "";
      const status = document.getElementById("cryptoStatus");
      const sendBtn = document.getElementById("sendBtn");

      if (!message.trim() || passphrase.length < 10) {
        if (status) status.textContent = "Isi pesan dan passphrase minimal 10 karakter.";
        return;
      }

      encryptBtn.disabled = true;
      if (sendBtn) sendBtn.disabled = true;
      if (status) status.textContent = "Sedang mengenkripsi pesan...";

      try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await derive(passphrase, salt);
        const encrypted = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          key,
          enc.encode(message)
        );

        const demoKeys = await makeDemoKeys();
        const signature = await signDemo(message, demoKeys);

        document.getElementById("ciphertext").value = hex(encrypted);
        document.getElementById("salt").value = hex(salt);
        document.getElementById("iv").value = hex(iv);
        document.getElementById("signature").value = JSON.stringify(signature);
        document.getElementById("pubkey").value = JSON.stringify(signature.pub);

        if (sendBtn) sendBtn.disabled = false;
        if (status) status.textContent = "Enkripsi berhasil. Pesan siap dikirim.";
      } catch (error) {
        console.error("Kesalahan enkripsi:", error);
        if (status) status.textContent = "Enkripsi gagal: " + error.name + " - " + error.message;
      } finally {
        encryptBtn.disabled = false;
      }
    });
  }

  // BAGIAN DEKRIPSI UNTUK HALAMAN view_message.html
  const decryptBtn = document.getElementById("decryptBtn");
  if (decryptBtn) {
    decryptBtn.addEventListener("click", async () => {
      const dataElement = document.getElementById("securevault-message");
      const passphrase = document.getElementById("passphrase")?.value ?? "";
      const status = document.getElementById("verifyStatus");
      const output = document.getElementById("plainOutput");

      if (!dataElement) {
        if (status) status.textContent = "Data pesan tidak ditemukan pada halaman.";
        return;
      }
      if (!passphrase) {
        if (status) status.textContent = "Masukkan passphrase terlebih dahulu.";
        return;
      }

      decryptBtn.disabled = true;
      if (status) status.textContent = "Sedang mendekripsi pesan...";
      if (output) output.textContent = "";

      try {
        const messageData = JSON.parse(dataElement.textContent);
        const salt = unhex(messageData.salt);
        const iv = unhex(messageData.iv);
        const ciphertext = unhex(messageData.ciphertext);

        if (salt.length !== 16) throw new Error("Panjang salt tidak sesuai (harus 16 byte).");
        if (iv.length !== 12) throw new Error("Panjang IV tidak sesuai (harus 12 byte).");
        if (ciphertext.length < 16) throw new Error("Ciphertext terlalu pendek atau tidak lengkap.");

        const key = await derive(passphrase, salt);
        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          key,
          ciphertext
        );
        const plaintext = dec.decode(decrypted);

        if (output) output.textContent = plaintext;

        let signatureValid = false;
        try {
          const signature = typeof messageData.signature === "string"
            ? JSON.parse(messageData.signature)
            : messageData.signature;
          signatureValid = await verifyDemo(plaintext, signature);
        } catch (signatureError) {
          console.error("Data tanda tangan tidak dapat dibaca:", signatureError);
        }

        if (status) {
          status.textContent = signatureValid
            ? "Dekripsi berhasil. Tanda tangan demo cocok."
            : "Dekripsi berhasil, tetapi tanda tangan demo tidak valid atau tidak dapat dibaca.";
        }
      } catch (error) {
        console.error("Detail kegagalan dekripsi:", error);
        if (status) {
          status.textContent = "ERROR BARU: " + error.name + " - " + error.message;
        }
      } finally {
        decryptBtn.disabled = false;
      }
    });
  }
});
