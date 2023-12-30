// gerar um par de chaves RSA para cada usuário
async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: { name: "SHA-256" },
      },
      true,
      ["encrypt", "decrypt"]
    );
  
    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  
    return {
      public_key: Buffer.from(publicKey).toString("base64"),
      private_key: Buffer.from(privateKey).toString("base64"),
    };
  }
  
  // cifrar a chave AES usando a chave pública de um destinatário
  async function encryptAesKey(aesKey, publicKey) {
    const keyBuffer = new Uint8Array(atob(publicKey).split('').map(char => char.charCodeAt(0)));
    const importedKey = await crypto.subtle.importKey(
      "spki",
      keyBuffer,
      { name: "RSA-OAEP", hash: { name: "SHA-256" } },
      false,
      ["encrypt"]
    );
  
    // Convert aesKey to Uint8Array directly without using atob
    const aesKeyBuffer = new Uint8Array(aesKey.split('').map(char => char.charCodeAt(0)));
  
    const encryptedAesKey = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      importedKey,
      aesKeyBuffer
    );
  
    // Convert the encrypted data to base64
    const encryptedAesKeyBase64 = btoa(String.fromCharCode.apply(null, new Uint8Array(encryptedAesKey)));
  
    return encryptedAesKeyBase64;
  }
  
  
  // decifrar a chave AES usando a chave privada do destinatário
  async function decryptAesKey(encryptedAesKey, privateKey) {
    const keyBuffer = Buffer.from(privateKey, "base64");
    const key = await crypto.subtle.importKey(
      "pkcs8",
      keyBuffer,
      { name: "RSA-OAEP", hash: { name: "SHA-256" } },
      false,
      ["decrypt"]
    );
  
    const decryptedAesKey = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      key,
      Buffer.from(encryptedAesKey, "base64")
    );
  
    return Buffer.from(decryptedAesKey).toString("base64");
  }
  
  // cifrar uma mensagem usando a chave AES
  async function encryptMessage(message, aesKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await crypto.subtle.importKey(
      "raw",
      Buffer.from(aesKey, "base64"),
      { name: "AES-GCM" },
      true,
      ["encrypt"]
    );
  
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(message)
    );
  
    const tag = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  
    return {
      ciphertext: Buffer.from(ciphertext).toString("base64"),
      nonce: Buffer.from(iv).toString("base64"),
      tag: Buffer.from(tag).toString("base64"),
    };
  }
  
  // decifrar uma mensagem usando a chave AES
  async function decryptMessage(nonce, ciphertext, tag, aesKey) {
    const iv = Buffer.from(nonce, "base64");
    const key = await crypto.subtle.importKey(
      "raw",
      Buffer.from(aesKey, "base64"),
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
  
    const decryptedMessage = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: new Uint8Array(0), tagLength: 128 },
      key,
      Buffer.from(ciphertext, "base64")
    );
  
    return new TextDecoder().decode(decryptedMessage);
  }

  module.exports = {
    encryptAesKey,
  };
  