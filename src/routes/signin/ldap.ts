import { RequestHandler } from 'express';
import { authenticate } from 'ldap-authentication';

import {
  getUserByEmail,
  ENV,
  getGravatarUrl,
  insertUser,
  getSignInResponse,
  gqlSdk,
} from '@/utils';
import { logger } from '@/logger';
import { sendError } from '@/errors';
import { Joi, password } from '@/validation';
import { InsertUserMutation } from '@/utils/__generated__/graphql-request';
import { createHasuraAccessToken } from '@/utils/jwt';
import { getNewRefreshToken } from '@/utils/refresh-token';
import { castObjectEnv } from '@/config/utils';
const provider = 'ldap';

export type LdapAttr = {
  email: string;
  name: string;
  phone: string;
  avatar: string;
};

export const ldapSignInSchema = Joi.object({
  username: Joi.string().min(1).required(),
  password: password.required(),
}).meta({ className: 'LdapSignInSchema' });

export const ldapSignInHandler: RequestHandler<
  {},
  {},
  {
    username: string;
    password: string;
  }
> = async (req, res) => {
  const { username, password } = req.body;
  logger.info(`Sign in with usernamme: ${username}`);

  if (process.env.AUTH_PROVIDER_LDAP_ENABLED == 'false') {
    return sendError(res, 'internal-error');
  }
  let user: NonNullable<InsertUserMutation['insertUser']> | null = null;
  let ldapUserProfile: any;
  const ldap_attr = castObjectEnv<LdapAttr>('AUTH_PROVIDER_LDAP_FIELDS');
  // LDAP
  // Authentication
  // Code
  //   let search_base = process.env.AUTH_PROVIDER_LDAP_OU
  //   if(process.env.AUTH_PROVIDER_LDAP_OU) {
  //     search_base = `ou=${process.env.AUTH_PROVIDER_LDAP_OU},${process.env.AUTH_PROVIDER_LDAP_DN}`
  //   } else {
  //     search_base = `${process.env.AUTH_PROVIDER_LDAP_DN}`
  //   }
  //   const dn = `${process.env.AUTH_PROVIDER_LDAP_UID}=${username},${search_base}`
  const options = {
    ldapOpts: {
      url: process.env.AUTH_PROVIDER_LDAP_URL || 'http://localhost:389',
      // tlsOptions: { rejectUnauthorized: false }
    },
    userDn: username, // from ENV
    userPassword: password,
    userSearchBase: process.env.AUTH_PROVIDER_LDAP_SB, // from ENV
    usernameAttribute: process.env.AUTH_PROVIDER_LDAP_USERNAME_ATTR, //to do from ENV
    username: username,
    attributes: [
      ldap_attr.email,
      ldap_attr.name,
      ldap_attr.avatar,
      ldap_attr.phone,
    ],
    // attributes: [ldap_attr.email,ldap_attr.phone]
    // starttls: false
  };

  try {
    ldapUserProfile = await authenticate(options);
  } catch {
    return sendError(res, 'invalid-email-password');
  }
  logger.info(ldapUserProfile);
  //user profile

  const {
    authUserProviders: [authUserProvider],
  } = await gqlSdk.authUserProviders({
    provider: provider, //provider
    providerUserId: username, //cn
  });

  if (authUserProvider) {
    // * The userProvider already exists. Update it with the new tokens
    user = authUserProvider.user;
    const accessToken = await createHasuraAccessToken(user);
    const { refreshToken } = await getNewRefreshToken(user.id);
    await gqlSdk.updateAuthUserprovider({
      id: authUserProvider.id,
      authUserProvider: {
        accessToken: accessToken,
        refreshToken: refreshToken,
      },
    });
  } else {
    if (username) {
      user = await getUserByEmail(ldapUserProfile[ldap_attr.email]);
    }
    if (!user) {
      if(process.env.AUTH_PROVIDER_LDAP_ALLOW_AUTO_SIGNUP == 'false') return sendError(res, 'user-not-found');
      // * No user found with this email. Create a new user
      const passwordHash = null;
      const email = ldapUserProfile[ldap_attr.email];
      const defaultRole = ENV.AUTH_USER_DEFAULT_ROLE;
      const roles = {
        data: ENV.AUTH_USER_DEFAULT_ALLOWED_ROLES.map((role) => ({
          role,
        })),
      };
      const locale = ENV.AUTH_LOCALE_DEFAULT;
      const displayName = ldapUserProfile[ldap_attr.name];
      const avatarUrl = getGravatarUrl(email) || '';
      user = await insertUser({
        passwordHash,
        email,
        defaultRole,
        roles,
        locale,
        displayName,
        avatarUrl,
      });
    }
    if (user) {
      const accessToken = await createHasuraAccessToken(user);
      const { refreshToken } = await getNewRefreshToken(user.id);
      const { insertAuthUserProvider } = await gqlSdk.insertUserProviderToUser({
        userProvider: {
          userId: user.id,
          providerId: provider, //ldap
          providerUserId: username, //cn
          accessToken: accessToken,
          refreshToken: refreshToken,
        },
      });
      if (!insertAuthUserProvider) {
        logger.warn('Could not add a provider to user');
        return sendError(res, 'internal-error', {}, true);
      }
    } else {
      logger.warn('Could not find or create user');
      return sendError(res, 'internal-error', {}, true);
    }
  }

  if (user) {
    if(user.disabled) return sendError(res, 'disabled-user', {}, true);
    if(!user.emailVerified) return sendError(res, 'unverified-user', {}, true);
    const signInTokens = await getSignInResponse({
      userId: user.id,
      checkMFA: false,
    });

    return res.send(signInTokens);
  }

  logger.error('Could not retrieve user ID');
  return sendError(res, 'user-not-found');
};
