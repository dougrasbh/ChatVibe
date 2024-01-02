import forge from 'node-forge'

export async function generateRsaKeyPair() {
  const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 })
  const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey)
  const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey)
  localStorage.setItem('userPrivateKey', privateKeyPem)
  return publicKeyPem
}

export async function encryptAesKey(aesKey, rsaUserPublicKey) {
  const publicKey = forge.pki.publicKeyFromPem(rsaUserPublicKey)
  //console.log(publicKey)
  const aesKeyBytes = forge.util.createBuffer(aesKey)
  const encryptedAesKey = publicKey.encrypt(aesKeyBytes.getBytes(), 'RSA-OAEP')
  const encryptedAesKeyBase64 = forge.util.encode64(encryptedAesKey)
  return encryptedAesKeyBase64
}

export async function decryptAesKey(encryptedAesKeyBase64, rsaUserPrivateKey) {
  const privateKey = forge.pki.privateKeyFromPem(rsaUserPrivateKey)
  //console.log(encryptedAesKeyBase64)
  const encryptedAesKey = forge.util.decode64(encryptedAesKeyBase64)
  const decryptedAesKeyBytes = privateKey.decrypt(encryptedAesKey, 'RSA-OAEP')
  const decryptedAesKey = forge.util.bytesToHex(decryptedAesKeyBytes);
  return decryptedAesKey
}

export async function encryptMessage(textToEncrypt, aesKey) {
  const aesKeyBuffer = forge.util.createBuffer(forge.util.decode64(aesKey))
  const textBuffer = forge.util.createBuffer(textToEncrypt, 'utf8');
  const cipher = forge.cipher.createCipher('AES-ECB', aesKeyBuffer);
  cipher.start();
  cipher.update(textBuffer);
  cipher.finish();
  const encryptedBytes = cipher.output.getBytes();
  const encryptedString = forge.util.encode64(encryptedBytes);
  return encryptedString
}

export async function decryptMessage(encryptedString, aesKey) {
  const aesKeyBuffer = forge.util.createBuffer(forge.util.decode64(aesKey))
  const encryptedBytes = forge.util.decode64(encryptedString)
  const encryptedBuffer = forge.util.createBuffer(encryptedBytes)
  const decipher = forge.cipher.createDecipher('AES-ECB', aesKeyBuffer)
  decipher.start()
  decipher.update(encryptedBuffer)
  decipher.finish()
  const decryptedBytes = decipher.output.getBytes();
  const decryptedString = forge.util.decodeUtf8(decryptedBytes)
  return decryptedString
}

  