import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Shield, Loader2 } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export function LoginForm() {
  const { login, isLoading, error } = useAuth();
  const [localLoading, setLocalLoading] = useState(false);

  const handleLogin = async () => {
    setLocalLoading(true);
    await login();
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background grid-bg p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center pb-2">
          <div className="flex justify-center mb-4">
            <div className="p-4 rounded-2xl bg-primary/20 border border-primary/50">
              <Shield className="w-12 h-12 text-primary" />
            </div>
          </div>
          <CardTitle className="text-2xl font-display">SOC Command Center</CardTitle>
          <p className="text-muted-foreground">
            Sign in to access the security dashboard
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          {error && (
            <div className="p-3 rounded-lg bg-destructive/20 border border-destructive/50 text-destructive text-sm">
              {error}
            </div>
          )}

          <Button
            className="w-full"
            size="lg"
            onClick={handleLogin}
            disabled={isLoading || localLoading}
          >
            {(isLoading || localLoading) ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Connecting...
              </>
            ) : (
              <>
                <Shield className="w-4 h-4 mr-2" />
                Sign in with SSO
              </>
            )}
          </Button>

          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t border-border" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-card px-2 text-muted-foreground">
                Or continue with
              </span>
            </div>
          </div>

          <form className="space-y-4" onSubmit={(e) => e.preventDefault()}>
            <div>
              <Input
                type="email"
                placeholder="Email address"
                disabled
                className="opacity-50"
              />
            </div>
            <div>
              <Input
                type="password"
                placeholder="Password"
                disabled
                className="opacity-50"
              />
            </div>
            <Button
              type="submit"
              variant="outline"
              className="w-full"
              disabled
            >
              Local login disabled
            </Button>
          </form>

          <p className="text-xs text-center text-muted-foreground">
            By signing in, you agree to the organization's security policies.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
