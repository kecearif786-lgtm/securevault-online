const enc = new TextEncoder();
const dec = new TextDecoder();
const hex = b => Array.from(new Uint8Array(b), x => x.toString(16).padStart(2, "0")).join("");
const unhex = h => new Uint8Array((h.match(/.{1,2}/g) || []).map(x => parseInt(x, 16)));
async function derive(pass, salt) {
  const material = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt, iterations:200000, hash:"SHA-256"},
    material, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
}
/* Skema tanda tangan Dissanayake dari prototipe awal.
   Hanya demonstrasi akademik: ukuran kunci dan konstruksi belum diaudit. */
function modPow(b,e,m){let r=1n;b%=m;while(e>0n){if(e&1n)r=r*b%m;b=b*b%m;e>>=1n;}return r;}
function egcd(a,b){if(b===0n)return[a,1n,0n];const[g,x,y]=egcd(b,a%b);return[g,y,x-a/b*y];}
function inv(a,m){const[g,x]=egcd((a%m+m)%m,m);if(g!==1n)throw Error("Inverse tidak tersedia");return(x%m+m)%m;}
function randomBig(bits){const a=crypto.getRandomValues(new Uint8Array(bits/8));a[0]|=0xC0;a[a.length-1]|=1;return BigInt("0x"+hex(a));}
function probablePrime(n){if(n<2n)return false;for(const p of [2n,3n,5n,7n,11n,13n,17n,19n,23n]){if(n===p)return true;if(n%p===0n)return false;}let d=n-1n,s=0;while(d%2n===0n){d/=2n;s++;}for(let i=0;i<12;i++){let a=BigInt(2+Math.floor(Math.random()*1000000));let x=modPow(a,d,n);if(x===1n||x===n-1n)continue;let ok=false;for(let j=1;j<s;j++){x=x*x%n;if(x===n-1n){ok=true;break;}}if(!ok)return false;}return true;}
function prime(bits){for(let i=0;i<100000;i++){const n=randomBig(bits);if(probablePrime(n))return n;}throw Error("Gagal membuat kunci demo");}
async function digestBig(message){const h=await crypto.subtle.digest("SHA-256",enc.encode(message));return BigInt("0x"+hex(h));}
async function makeDemoKeys(){const p=prime(256);let q=prime(256);while(q===p)q=prime(256);const n=p*q,phi=(p-1n)*(q-1n),d=65537n,e=inv(d,phi);return {n:n.toString(),e:e.toString(),d:d.toString()};}
async function signDemo(message, keys){const M=await digestBig(message);let r=0n;while((M+r)%4n!==0n)r++;const a=M+r-2n;return {S:modPow(a,BigInt(keys.d),BigInt(keys.n)).toString(16),r:r.toString(),pub:{n:keys.n,e:keys.e}};}
async function verifyDemo(message,sig){try{const M=await digestBig(message),a=M+BigInt(sig.r)-2n;return modPow(BigInt("0x"+sig.S),BigInt(sig.pub.e),BigInt(sig.pub.n))===a;}catch{return false;}}
document.addEventListener("DOMContentLoaded",()=>{
 const encryptBtn=document.getElementById("encryptBtn");
 if(encryptBtn) encryptBtn.addEventListener("click",async()=>{
  const message=document.getElementById("plain").value,pass=document.getElementById("passphrase").value,status=document.getElementById("cryptoStatus");
  if(!message||pass.length<10){status.textContent="Isi pesan dan passphrase minimal 10 karakter.";return;}
  encryptBtn.disabled=true;status.textContent="Sedang mengenkripsi dan membuat tanda tangan demo…";
  try{
   const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12)),key=await derive(pass,salt);
   const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(message));
   const keys=await makeDemoKeys(),sig=await signDemo(message,keys);
   document.getElementById("ciphertext").value=hex(ct);document.getElementById("salt").value=hex(salt);document.getElementById("iv").value=hex(iv);
   document.getElementById("signature").value=JSON.stringify(sig);document.getElementById("pubkey").value=JSON.stringify(sig.pub);
   document.getElementById("sendBtn").disabled=false;status.textContent="Enkripsi berhasil. Pesan siap dikirim.";
  }catch(e){status.textContent="Gagal: "+e.message;}finally{encryptBtn.disabled=false;}
 });
 const decryptBtn=document.getElementById("decryptBtn");
 if(decryptBtn) decryptBtn.addEventListener("click",async()=>{
  const dataElement = document.getElementById("securevault-message");
const m = dataElement ? JSON.parse(dataElement.textContent) : null;

const pass = document.getElementById("passphrase").value;
const status = document.getElementById("verifyStatus");
const out = document.getElementById("plainOutput");

if (!m) {
    throw new Error("Data pesan tidak ditemukan.");
}

if (!pass) {
    status.textContent = "Masukkan passphrase terlebih dahulu.";
    return;
}
   try{
   const key=await derive(pass,unhex(m.salt));const plain=dec.decode(await crypto.subtle.decrypt({name:"AES-GCM",iv:unhex(m.iv)},key,unhex(m.ciphertext)));
   const sig=JSON.parse(m.signature),valid=await verifyDemo(plain,sig);out.textContent=plain;
   status.textContent=valid?"Dekripsi berhasil. Tanda tangan demo cocok.":"Pesan terbuka, tetapi tanda tangan demo tidak valid.";
  }catch(e){out.textContent="";status.textContent="Dekripsi gagal. Periksa passphrase atau integritas data.";}
 });
});
