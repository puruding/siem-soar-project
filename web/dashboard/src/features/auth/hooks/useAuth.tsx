import { useEffect, useCallback } from 'react';
import Keycloak from 'keycloak-js';
import { useAuthStore, User } from '../store/authStore';

// Keycloak configuration
const keycloakConfig = {
  url: import.meta.env.VITE_KEYCLOAK_URL || 'http://localhost:8080',
  realm: import.meta.env.VITE_KEYCLOAK_REALM || 'soc',
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID || 'soc-dashboard',
};

// Initialize Keycloak instance
const keycloak = new Keycloak(keycloakConfig);

export function useAuth() {
  const {
    user,
    token,
    isAuthenticated,
    isLoading,
    error,
    setUser,
    setTokens,
    setLoading,
    setError,
    logout: clearAuth,
    hasRole,
    hasPermission,
  } = useAuthStore();

  // Initialize Keycloak on mount
  useEffect(() => {
    const initKeycloak = async () => {
      setLoading(true);
      try {
        const authenticated = await keycloak.init({
          onLoad: 'check-sso',
          silentCheckSsoRedirectUri:
            window.location.origin + '/silent-check-sso.html',
          pkceMethod: 'S256',
        });

        if (authenticated) {
          updateAuthState();
        }
      } catch (err) {
        console.error('Keycloak init error:', err);
        setError('Failed to initialize authentication');
      } finally {
        setLoading(false);
      }
    };

    // Only init if not already authenticated from storage
    if (!isAuthenticated) {
      initKeycloak();
    } else {
      setLoading(false);
    }

    // Setup token refresh
    keycloak.onTokenExpired = () => {
      keycloak
        .updateToken(30)
        .then(() => {
          updateAuthState();
        })
        .catch(() => {
          clearAuth();
        });
    };
  }, []);

  const updateAuthState = useCallback(() => {
    if (keycloak.token && keycloak.refreshToken && keycloak.tokenParsed) {
      const tokenData = keycloak.tokenParsed as {
        sub?: string;
        preferred_username?: string;
        email?: string;
        name?: string;
        realm_access?: { roles?: string[] };
        groups?: string[];
      };

      const userData: User = {
        id: tokenData.sub || '',
        username: tokenData.preferred_username || '',
        email: tokenData.email || '',
        name: tokenData.name || '',
        roles: tokenData.realm_access?.roles || [],
        groups: tokenData.groups || [],
      };

      setUser(userData);
      setTokens(keycloak.token, keycloak.refreshToken);
    }
  }, [setUser, setTokens]);

  const login = useCallback(async () => {
    setLoading(true);
    try {
      await keycloak.login({
        redirectUri: window.location.origin + '/dashboard',
      });
    } catch (err) {
      console.error('Login error:', err);
      setError('Login failed');
      setLoading(false);
    }
  }, [setLoading, setError]);

  const logout = useCallback(async () => {
    setLoading(true);
    try {
      await keycloak.logout({
        redirectUri: window.location.origin,
      });
      clearAuth();
    } catch (err) {
      console.error('Logout error:', err);
      clearAuth();
    } finally {
      setLoading(false);
    }
  }, [setLoading, clearAuth]);

  const getToken = useCallback(async (): Promise<string | null> => {
    try {
      // Refresh if token expires in less than 30 seconds
      await keycloak.updateToken(30);
      return keycloak.token || token;
    } catch {
      return token;
    }
  }, [token]);

  return {
    user,
    token,
    isAuthenticated,
    isLoading,
    error,
    login,
    logout,
    getToken,
    hasRole,
    hasPermission,
  };
}

// HOC for protected routes
export function withAuth<P extends object>(
  Component: React.ComponentType<P>,
  requiredRoles?: string[]
) {
  return function AuthenticatedComponent(props: P) {
    const { isAuthenticated, isLoading, login, hasRole } = useAuth();

    useEffect(() => {
      if (!isLoading && !isAuthenticated) {
        login();
      }
    }, [isLoading, isAuthenticated, login]);

    if (isLoading) {
      return (
        <div className="flex items-center justify-center h-screen">
          <div className="text-center">
            <div className="w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-muted-foreground">Authenticating...</p>
          </div>
        </div>
      );
    }

    if (!isAuthenticated) {
      return null;
    }

    // Check required roles
    if (requiredRoles && requiredRoles.length > 0) {
      const hasRequiredRole = requiredRoles.some((role) => hasRole(role));
      if (!hasRequiredRole) {
        return (
          <div className="flex items-center justify-center h-screen">
            <div className="text-center">
              <h1 className="text-2xl font-bold text-destructive mb-2">
                Access Denied
              </h1>
              <p className="text-muted-foreground">
                You don't have permission to access this page.
              </p>
            </div>
          </div>
        );
      }
    }

    return <Component {...props} />;
  };
}
