import * as crypto from 'crypto';
import * as fs from 'fs';

export function decryptText(encryptedText: any) {
  return crypto.privateDecrypt(
    {
      key: fs.readFileSync('private_key.pem', 'utf8'),
      // In order to decrypt the data, we need to specify the
      // same hashing function and padding scheme that we used to
      // encrypt the data in the previous step
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    encryptedText
  );
}

const password =
  'AdAIFMyJt7ZMTT8EVW9KCp2kYYEwT6Ez2sSq8pK/AOgUsnXvm4A8aB+HYbDMhF4KqoDK7pT+TGy1Z4UmQOUHZSbPUVJNBHSaRfturMzrErF5K0fIzX+HkEfid5/j7kXAJi8cRtZwO7kiRJjk6X7aup6PeUMDCHwRtULCtvRYOztqaCntJ2Z/BLOdhDlieDKQqyeZh29iTcZNK3/yPc1cBduYoIWwL0gDLzN2t4Ax7PX6/HONpxu6iklMiiaEDi1nYBS8ONCBGMXk8WWDc/MlB94DodAbLLE/7M5dWVuJ/L9WJPiacOZrK5g1joFxVgynPpdZY9ndvNu4zLDYN2vQqg==';
const decryptedPassword = decryptText(Buffer.from(password, 'base64'));
console.log(decryptedPassword.toString());
