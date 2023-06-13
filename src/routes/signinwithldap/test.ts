import { authenticate } from 'ldap-authentication'

async function auth() {
  // auth with admin
  // let options = {
  //   ldapOpts: {
  //     url: 'ldap://127.0.0.1:389',
  //     // tlsOptions: { rejectUnauthorized: false }
  //   },
  //   adminDn: 'cn=admin,ou=users,dc=mtr,dc=com',
  //   adminPassword: 'itachi',
  //   userPassword: 'itachi',
  //   userSearchBase: 'ou=users,dc=mtr,dc=com',
  //   usernameAttribute: 'uid',
  //   username: 'admin',
  //   // starttls: false
  // }

  const userOtions = {
    ldapOpts: {
      url: 'ldap://ldap.forumsys.com:389',
      // tlsOptions: { rejectUnauthorized: false }
    },
    // adminDn: 'cn=admin,ou=users,dc=mtr,dc=com',
    // adminPassword: 'itachi',
    userDn: 'uid=curie,dc=example,dc=com',
    userPassword: 'password',
    userSearchBase: 'dc=example,dc=com',
    usernameAttribute: 'uid',
    username: 'curie',
    attributes: ['mail','cn'],
    // starttls: false
  }

//   let authenticated = await authenticate({
//   ldapOpts: { url: 'ldap://127.0.0.1:8389' },
//   userDn: 'cn=comptrac\\comptrac,cn=Users,dc=comptrac,dc=com',
//   userPassword: 'Secure@C',
// })

  // const authenticated = await authenticate({
  //   ldapOpts: { url: 'ldap://127.0.0.1:389' },
  //   userDn: 'cn=nimal@gmail.com,ou=users,dc=mtr,dc=com',
  //   userPassword: 'itachi',
  //   userSearchBase: 'ou=users,dc=mtr,dc=com',
  //   usernameAttribute: 'uid',
  //   username: 'nimal@gmail.com',
  // })

  const user = await authenticate(userOtions)

  console.log(user)
}

auth()