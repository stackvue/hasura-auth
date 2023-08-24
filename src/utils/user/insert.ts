import { gqlSdk } from '../gql-sdk';
import { ENV } from '../env';
import {
  InsertUserMutation,
  InsertUserMutationVariables,
} from '../__generated__/graphql-request';

type UserInput = InsertUserMutationVariables['user'];
type UserOutput = NonNullable<InsertUserMutation['insertUser']>;

export const insertUser = async (user: UserInput): Promise<UserOutput> => {
  const { insertUser } = await gqlSdk.insertUser({
    user,
  });
  if (!insertUser) {
    throw new Error('Could not insert user');
  }

  const profile = {
    auth_id: insertUser.id,
    user_id: insertUser.id,
    display_name: insertUser.displayName,
    role: user.defaultRole,
    disabled: ENV.AUTH_DISABLE_NEW_USERS,
    email: insertUser.email,
    email_verified: false,
    first_name: user.metadata?.firstName,
    last_name: user.metadata?.lastName,
    tenant_id: user.metadata?.tenantId,
    function_id: user.metadata?.functionId,
    created_by: user.metadata?.createdBy,
    updated_by: user.metadata?.createdBy,
  };

  const { insert_comptrac_user_profiles_one } = await gqlSdk.insertUserProfile({
    profile,
  });  

  if (!insert_comptrac_user_profiles_one) {
    await gqlSdk.deleteUser({
      userId: insertUser.id,
    });
    throw new Error('Could not insert user profile');
  }
  return insertUser;
};
