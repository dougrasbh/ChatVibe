import forge from 'node-forge'

function generateRsaKeyPair() {
  const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });

  const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);
  const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);

  return { privateKeyPem, publicKeyPem }
}

// Exemplo de uso
// const { privateKeyPem, publicKeyPem } = generateRsaKeyPair();
// console.log('Chave Privada RSA:', privateKeyPem);
// console.log('Chave Pública RSA:', publicKeyPem);

  
  // cifrar a chave AES usando a chave pública de um destinatário
  // async function encryptAesKey(aesKey, publicKey) {
  //   try {
  //     const keyBuffer = new Uint8Array(
  //       atob(publicKey)
  //         .split("")
  //         .map((char) => char.charCodeAt(0))
  //     );
  //     const key = await crypto.subtle.importKey(
  //       "spki",
  //       keyBuffer,
  //       { name: "RSA-OAEP", hash: { name: "SHA-256" } },
  //       false,
  //       ["encrypt"]
  //     );
  
  //     const encryptedAesKey = await crypto.subtle.encrypt(
  //       { name: "RSA-OAEP" },
  //       key,
  //       aesKey
  //     );
  
  //     // Convert the encrypted data to base64
  //     const encryptedAesKeyBase64 = btoa(
  //       String.fromCharCode.apply(null, new Uint8Array(encryptedAesKey))
  //     );
  
  //     return encryptedAesKeyBase64;
  //   } catch (error) {
  //     console.error("Error encrypting AES key:", error);
  //     throw error; // Rethrow the error to indicate that something went wrong
  //   }
  // }

  export async function encryptAesKey(aesKey, rsaUserPublicKey) {
    // Criar uma instância do objeto RSA Key
    const publicKey = forge.pki.publicKeyFromPem(rsaUserPublicKey)
  
    // Converter a chave AES para bytes
    const aesKeyBytes = forge.util.createBuffer(aesKey);
  
    // Criptografar a chave AES usando RSA
    const encryptedAesKey = publicKey.encrypt(aesKeyBytes.getBytes(), 'RSA-OAEP');
  
    // Obter o resultado criptografado em base64
    const encryptedAesKeyBase64 = forge.util.encode64(encryptedAesKey);
  
    // Exibir a chave AES criptografada
    console.log('Chave AES criptografada (base64):', encryptedAesKeyBase64);
  
    // Retornar a chave AES criptografada em base64 como string
    return encryptedAesKeyBase64;
  };
  
  
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

  