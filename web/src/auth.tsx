import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { api, setCsrfToken } from "./api";
import type { Account } from "./api";

interface AuthState {
  /** undefined while checking the session, null when logged out */
  email: string | null | undefined;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, consent: boolean) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [email, setEmail] = useState<string | null | undefined>(undefined);

  const accept = useCallback((account: Account) => {
    setCsrfToken(account.csrf_token);
    setEmail(account.email);
  }, []);

  useEffect(() => {
    api
      .me()
      .then(accept)
      .catch(() => setEmail(null));
  }, [accept]);

  const value = useMemo<AuthState>(
    () => ({
      email,
      login: async (e, p) => accept(await api.login(e, p)),
      register: async (e, p, c) => accept(await api.register(e, p, c)),
      logout: async () => {
        await api.logout();
        setCsrfToken("");
        setEmail(null);
      },
    }),
    [email, accept],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
