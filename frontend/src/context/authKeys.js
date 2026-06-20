/**
 * Auth storage keys — isolated to prevent circular imports between
 * AuthContext (React) and api.js (module-level fetch helper).
 */
export const TOKEN_KEY = 'cybermeters_auth_token'
export const USER_KEY  = 'cybermeters_auth_user'
