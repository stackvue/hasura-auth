import { RequestHandler } from 'express';
import bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import * as fs from 'fs';

import { getSignInResponse, getUserByEmail, ENV } from '@/utils';
import { logger } from '@/logger';
import { sendError } from '@/errors';
import { Joi, email, password } from '@/validation';

export function decryptText(encryptedText: any) {
  return crypto.privateDecrypt(
    {
      key: fs.readFileSync(
        `${process.env.DECRYPTION_PRIVATE_KEY_PATH}`,
        'utf8'
      ),
      // In order to decrypt the data, we need to specify the
      // same hashing function and padding scheme that we used to
      // encrypt the data in the previous step
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    encryptedText
  );
}

export const signInEmailPasswordSchema = Joi.object({
  email: email.required(),
  password: password.required(),
}).meta({ className: 'SignInEmailPasswordSchema' });

export const signInEmailPasswordHandler: RequestHandler<
  {},
  {},
  {
    email: string;
    password: string;
  }
> = async (req, res) => {
  const { email, password } = req.body;
  logger.debug(`Sign in with email: ${email}`);

  const user = await getUserByEmail(email);

  if (!user) {
    return sendError(res, 'invalid-email-password');
  }

  if (user.disabled) {
    return sendError(res, 'disabled-user');
  }

  if (!user.passwordHash) {
    return sendError(res, 'invalid-email-password');
  }

  const decryptedPassword = decryptText(Buffer.from(password, 'base64'));
  const decryptedPasswordText = decryptedPassword.toString();
  const isPasswordCorrect = await bcrypt.compare(decryptedPasswordText, user.passwordHash);

  if (!isPasswordCorrect) {
    return sendError(res, 'invalid-email-password');
  }

  if (ENV.AUTH_EMAIL_SIGNIN_EMAIL_VERIFIED_REQUIRED && !user.emailVerified) {
    return sendError(res, 'unverified-user');
  }

  const signInTokens = await getSignInResponse({
    userId: user.id,
    checkMFA: true,
  });

  return res.send(signInTokens);
};
