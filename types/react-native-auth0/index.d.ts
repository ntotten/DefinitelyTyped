// Type definitions for react-native-auth0 2.3
// Project: https://github.com/auth0/react-native-auth0
// Definitions by: Andrea Ascari <https://github.com/ascariandrea>
//                 Mark Nelissen <https://github.com/marknelissen>
//                 Leo Farias <https://github.com/leoafarias>
//                 Nathan Totten <https://github.com/ntotten>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
// TypeScript Version: 3.7

export class BaseError extends Error {
    constructor(name: any, message: any);
    name: any;
    message: any;
  }

  export class AuthError extends BaseError {
    constructor(response: any);
    json: any;
    status: any;
  }
  export class Auth0Error extends BaseError {
    constructor(response: any);
    json: any;
    status: any;
    code: any;
  }

  export class Agent {
    show(url: any, closeOnLoad?: boolean): Promise<any>;
    newTransaction(): Promise<any>;
  }

  /**
   * Helper to perform Auth against Auth0 hosted login page
   *
   * It will use `/authorize` endpoint of the Authorization Server (AS)
   * with Code Grant and Proof Key for Challenge Exchange (PKCE).
   *
   * @export
   * @class WebAuth
   * @see https://auth0.com/docs/api-auth/grant/authorization-code-pkce
   */
  export class WebAuth {
    constructor(auth: any);
    client: any;
    domain: any;
    clientId: any;
    agent: Agent;
    /**
     * Starts the AuthN/AuthZ transaction against the AS in the in-app browser.
     *
     * In iOS it will use `SFSafariViewController` and in Android Chrome Custom Tabs.
     *
     * To learn more about how to customize the authorize call, check the Universal Login Page
     * article at https://auth0.com/docs/hosted-pages/login
     *
     * @param {Object} parameters parameters to send on the AuthN/AuthZ request.
     * @param {String} [parameters.state] random string to prevent CSRF attacks and used to discard unexepcted results. By default its a cryptographically secure random.
     * @param {String} [parameters.nonce] random string to prevent replay attacks of id_tokens.
     * @param {String} [parameters.audience] identifier of Resource Server (RS) to be included as audience (aud claim) of the issued access token
     * @param {String} [parameters.scope] scopes requested for the issued tokens. e.g. `openid profile`
     * @param {String} [parameters.connection] The name of the identity provider to use, e.g. "google-oauth2" or "facebook". When not set, it will display Auth0's Universal Login Page.
     * @param {Number} [parameters.max_age] The allowable elapsed time in seconds since the last time the user was authenticated (optional).
     * @param {Object} options options for ID token validation configuration.
     * @param {Number} [options.leeway] The amount of leeway, in seconds, to accommodate potential clock skew when validating an ID token's claims. Defaults to 60 seconds if not specified.
     * @returns {Promise}
     * @see https://auth0.com/docs/api/authentication#authorize-client
     *
     * @memberof WebAuth
     */
    authorize(
      parameters?: {
        state?: string;
        nonce?: string;
        audience?: string;
        scope?: string;
        connection?: string;
        max_age?: number;
      },
      options?: {
        leeway?: number;
      },
    ): Promise<any>;
    /**
     *  Removes Auth0 session and optionally remove the Identity Provider session.
     *
     *  In iOS it will use `SFSafariViewController` and in Android Chrome Custom Tabs.
     *
     * @param {Object} parameters parameters to send
     * @param {Bool} [parameters.federated] Optionally remove the IdP session.
     * @returns {Promise}
     * @see https://auth0.com/docs/logout
     *
     * @memberof WebAuth
     */
    clearSession(options?: {}): Promise<any>;
  }

  export class Client {
    constructor(options: any);
    telemetry: {
      name: any;
      version: any;
    };
    baseUrl: any;
    domain: any;
    bearer: string;
    post(
      path: any,
      body: any,
    ): Promise<
      | {
          json: any;
          status: number;
          ok: boolean;
          headers: Headers;
        }
      | {
          text: string;
          status: number;
          ok: boolean;
          headers: Headers;
        }
      | {
          text: string;
          status: number;
          ok: boolean;
          headers: Headers;
        }
    >;
    patch(
      path: any,
      body: any,
    ): Promise<
      | {
          json: any;
          status: number;
          ok: boolean;
          headers: Headers;
        }
      | {
          text: string;
          status: number;
          ok: boolean;
          headers: Headers;
        }
      | {
          text: string;
          status: number;
          ok: boolean;
          headers: Headers;
        }
    >;
    get(
      path: any,
      query: any,
    ): Promise<
      | {
          json: any;
          status: number;
          ok: boolean;
          headers: Headers;
        }
      | {
          text: string;
          status: number;
          ok: boolean;
          headers: Headers;
        }
      | {
          text: string;
          status: number;
          ok: boolean;
          headers: Headers;
        }
    >;
    url(path: any, query: any, includeTelemetry?: boolean): any;
    request(
      method: any,
      url: any,
      body: any,
    ): Promise<
      | {
          json: any;
          status: number;
          ok: boolean;
          headers: Headers;
        }
      | {
          text: string;
          status: number;
          ok: boolean;
          headers: Headers;
        }
      | {
          text: string;
          status: number;
          ok: boolean;
          headers: Headers;
        }
    >;
    _encodedTelemetry(): any;
  }

  /**
   * Auth0 Management API User endpoints
   *
   * @export
   * @see https://auth0.com/docs/api/management/v2#!/Users/
   * @class Users
   */
  export class Users {
    constructor(options?: {});
    client: Client;
    /**
     * @typedef {Object} Auth0User
     * @property {string} created_at
     * @property {string} email
     * @property {boolean} emailVerified
     * @property {[any]} identities
     * @property {string=} last_ip
     * @property {string=} last_login
     * @property {number} logins_count
     * @property {string=} picture
     * @property {string} updated_at
     * @property {string} userId
     * @property {any} userMetadata
     */
    /**
     * Returns the user by identifier
     *
     * @param {Object} parameters get user by identifier parameters
     * @param {String} parameters.id identifier of the user to obtain
     * @returns {Promise<Auth0User>}
     * @see https://auth0.com/docs/api/management/v2#!/Users/get_users_by_id
     *
     * @memberof Users
     */
    getUser(parameters?: {
      id: string;
    }): Promise<{
      created_at: string;
      email: string;
      emailVerified: boolean;
      identities: [any];
      last_ip?: string;
      last_login?: string;
      logins_count: number;
      picture?: string;
      updated_at: string;
      userId: string;
      userMetadata: any;
    }>;
    /**
     * Patch a user's `user_metadata`
     *
     * @param {Object} parameters patch user metadata parameters
     * @param {String} parameters.id identifier of the user to patch
     * @param {Object} parameters.metadata object with attributes to store in user_metadata.
     * @returns {Promise<Auth0User>}
     * @see https://auth0.com/docs/api/management/v2#!/Users/patch_users_by_id
     *
     * @memberof Users
     */
    patchUser(parameters?: {
      id: string;
      metadata: any;
    }): Promise<{
      created_at: string;
      email: string;
      emailVerified: boolean;
      identities: [any];
      last_ip?: string;
      last_login?: string;
      logins_count: number;
      picture?: string;
      updated_at: string;
      userId: string;
      userMetadata: any;
    }>;
  }

  /**
   * Auth0 Auth API
   *
   * @export Auth
   * @see https://auth0.com/docs/api/authentication
   * @class Auth
   */
  export class Auth {
    constructor(options?: {});
    client: Client;
    domain: any;
    clientId: any;
    /**
     * Builds the full authorize endpoint url in the Authorization Server (AS) with given parameters.
     *
     * @param {Object} parameters parameters to send to `/authorize`
     * @param {String} parameters.responseType type of the response to get from `/authorize`.
     * @param {String} parameters.redirectUri where the AS will redirect back after success or failure.
     * @param {String} parameters.state random string to prevent CSRF attacks.
     * @returns {String} authorize url with specified parameters to redirect to for AuthZ/AuthN.
     * @see https://auth0.com/docs/api/authentication#authorize-client
     *
     * @memberof Auth
     */
    authorizeUrl(parameters?: {
      responseType: string;
      redirectUri: string;
      state: string;
    }): string;
    /**
     * Builds the full logout endpoint url in the Authorization Server (AS) with given parameters.
     *
     * @param {Object} parameters parameters to send to `/v2/logout`
     * @param {Boolean} [parameters.federated] if the logout should include removing session for federated IdP.
     * @param {String} [parameters.clientId] client identifier of the one requesting the logout
     * @param {String} [parameters.returnTo] url where the user is redirected to after logout. It must be declared in you Auth0 Dashboard
     * @returns {String} logout url with specified parameters
     * @see https://auth0.com/docs/api/authentication#logout
     *
     * @memberof Auth
     */
    logoutUrl(parameters?: {
      federated?: boolean;
      clientId?: string;
      returnTo?: string;
    }): string;
    /**
     * Exchanges a code obtained via `/authorize` (w/PKCE) for the user's tokens
     *
     * @param {Object} parameters parameters used to obtain tokens from a code
     * @param {String} parameters.code code returned by `/authorize`.
     * @param {String} parameters.redirectUri original redirectUri used when calling `/authorize`.
     * @param {String} parameters.verifier value used to generate the code challenge sent to `/authorize`.
     * @returns {Promise<string>}
     * @see https://auth0.com/docs/api-auth/grant/authorization-code-pkce
     *
     * @memberof Auth
     */
    exchange(parameters?: {
      code: string;
      redirectUri: string;
      verifier: string;
    }): Promise<string>;
    /**
     * Exchanges an external token obtained via a native social authentication solution for the user's tokens
     *
     * @param {Object} parameters parameters used to obtain user tokens from an external provider's token
     * @param {String} parameters.subjectToken token returned by the native social authentication solution
     * @param {String} parameters.subjectTokenType identifier that indicates the native social authentication solution
     * @param {Object} [parameters.userProfile] additional profile attributes to set or override, only on select native social authentication solutions
     * @param {String} [parameters.audience] API audience to request
     * @param {String} [parameters.scope] scopes requested for the issued tokens. e.g. `openid profile`
     * @returns {Promise}
     *
     * @see https://auth0.com/docs/api/authentication#token-exchange-for-native-social
     *
     * @memberof Auth
     */
    exchangeNativeSocial(parameters?: {
      subjectToken: string;
      subjectTokenType: string;
      userProfile?: any;
      audience?: string;
      scope?: string;
    }): Promise<any>;
    /**
     * @typedef {Object} AuthResponse
     * @property {string} accessToken
     * @property {number} expiresIn
     * @property {string} idToken
     * @property {string} scope
     * @property {string} tokenType
     * @property {string=} refreshToken
     */
    /**
     * Performs Auth with user credentials using the Password Realm Grant
     *
     * @param {Object} parameters password realm parameters
     * @param {String} parameters.username user's username or email
     * @param {String} parameters.password user's password
     * @param {String} parameters.realm name of the Realm where to Auth (or connection name)
     * @param {String} [parameters.audience] identifier of Resource Server (RS) to be included as audience (aud claim) of the issued access token
     * @param {String} [parameters.scope] scopes requested for the issued tokens. e.g. `openid profile`
     * @returns {Promise<AuthResponse>}
     * @see https://auth0.com/docs/api-auth/grant/password#realm-support
     *
     * @memberof Auth
     */
    passwordRealm(parameters?: {
      username: string;
      password: string;
      realm: string;
      audience?: string;
      scope?: string;
    }): Promise<{
      accessToken: string;
      expiresIn: number;
      idToken: string;
      scope: string;
      tokenType: string;
      refreshToken?: string;
    }>;
    /**
     * Obtain new tokens using the Refresh Token obtained during Auth (requesting `offline_access` scope)
     *
     * @param {Object} parameters refresh token parameters
     * @param {String} parameters.refreshToken user's issued refresh token
     * @param {String} [parameters.scope] scopes requested for the issued tokens. e.g. `openid profile`
     * @returns {Promise}
     * @see https://auth0.com/docs/tokens/refresh-token/current#use-a-refresh-token
     *
     * @memberof Auth
     */
    refreshToken(parameters?: {
      refreshToken: string;
      scope?: string;
    }): Promise<any>;
    /**
     * Starts the Passworldess flow with an email connection
     *
     * @param {Object} parameters passwordless parameters
     * @param {String} parameters.email the email to send the link/code to
     * @param {String=} parameters.send the passwordless strategy, either 'link' or 'code'
     * @param {String=} parameters.authParams optional parameters, used when strategy is 'linḱ'
     * @returns {Promise}
     *
     * @memberof Auth
     */
    passwordlessWithEmail(parameters?: {
      email: string;
      send?: string;
      authParams?: string;
    }): Promise<any>;
    /**
     * Starts the Passworldess flow with an SMS connection
     *
     * @param {Object} parameters passwordless parameters
     * @param {String} parameters.phoneNumber the phone number to send the link/code to
     * @returns {Promise}
     *
     * @memberof Auth
     */
    passwordlessWithSMS(parameters?: { phoneNumber: string }): Promise<any>;
    /**
     * Finishes the Passworldess authentication with an email connection
     *
     * @param {Object} parameters passwordless parameters
     * @param {String} parameters.email the email where the link/code was received
     * @param {String} parameters.code the code numeric value (OTP)
     * @param {String} parameters.audience optional API audience to request
     * @param {String} parameters.scope optional scopes to request
     * @returns {Promise<AuthResponse>}
     *
     * @memberof Auth
     */
    loginWithEmail(parameters?: {
      email: string;
      code: string;
      audience: string;
      scope: string;
    }): Promise<{
      accessToken: string;
      expiresIn: number;
      idToken: string;
      scope: string;
      tokenType: string;
      refreshToken?: string;
    }>;
    /**
     * Finishes the Passworldess authentication with an SMS connection
     *
     * @param {Object} parameters passwordless parameters
     * @param {String} parameters.phoneNumber the phone number where the code was received
     * @param {String} parameters.code the code numeric value (OTP)
     * @param {String} parameters.audience optional API audience to request
     * @param {String} parameters.scope optional scopes to request
     * @returns {Promise<AuthResponse>}
     *
     * @memberof Auth
     */
    loginWithSMS(parameters?: {
      phoneNumber: string;
      code: string;
      audience: string;
      scope: string;
    }): Promise<{
      accessToken: string;
      expiresIn: number;
      idToken: string;
      scope: string;
      tokenType: string;
      refreshToken?: string;
    }>;
    /**
     * Revoke an issued refresh token
     *
     * @param {Object} parameters revoke token parameters
     * @param {String} parameters.refreshToken user's issued refresh token
     * @returns {Promise}
     *
     * @memberof Auth
     */
    revoke(parameters?: { refreshToken: string }): Promise<any>;
    /**
     * Return user information using an access token
     *
     * @param {Object} parameters user info parameters
     * @param {String} parameters.token user's access token
     * @returns {Promise}
     *
     * @memberof Auth
     */
    userInfo(parameters?: { token: string }): Promise<any>;
    /**
     * Request an email with instructions to change password of a user
     *
     * @param {Object} parameters reset password parameters
     * @param {String} parameters.email user's email
     * @param {String} parameters.connection name of the connection of the user
     * @returns {Promise}
     *
     * @memberof Auth
     */
    resetPassword(parameters?: {
      email: string;
      connection: string;
    }): Promise<any>;
    /**
     * @typedef {Object} CreateUserResponse
     * @property {string} Id
     * @property {boolean} emailVerified
     * @property {string} email
     */
    /**
     *
     *
     * @param {Object} parameters create user parameters
     * @param {String} parameters.email user's email
     * @param {String} [parameters.username] user's username
     * @param {String} parameters.password user's password
     * @param {String} parameters.connection name of the database connection where to create the user
     * @param {String} [parameters.metadata] additional user information that will be stored in `user_metadata`
     * @returns {Promise<CreateUserResponse>}
     *
     * @memberof Auth
     */
    createUser(parameters?: {
      email: string;
      username?: string;
      password: string;
      connection: string;
      metadata?: string;
    }): Promise<{
      Id: string;
      emailVerified: boolean;
      email: string;
    }>;
  }

  /**
   * Auth0 for React Native client
   *
   * @export
   * @class Auth0
   */
  export default class Auth0 {
    /**
     * Creates an instance of Auth0.
     * @param {Object} options your Auth0 application information
     * @param {String} options.domain your Auth0 domain
     * @param {String} options.clientId your Auth0 application client identifier
     *
     * @memberof Auth0
     */
    constructor(options?: { domain: string; clientId: string });
    auth: Auth;
    webAuth: WebAuth;
    options: {
      domain: string;
      clientId: string;
    };
    /**
     * Creates a Users API client
     * @param  {String} token for Management API
     * @return {Users}
     */
    users(token: string): Users;
  }
