/** Current-user context, backed by the session cookie. */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { createContext, useContext, useMemo, type ReactNode } from 'react';

import { ApiError, api } from '@/lib/api-client';
import type { AuthMethods, CurrentUser, LoginResult } from '@/lib/types';

interface AuthState {
  user: CurrentUser | null;
  methods: AuthMethods | null;
  loading: boolean;
  can: (permission: string) => boolean;
  /**
   * First sign-in step. A session is opened only when no second factor is
   * needed; otherwise the caller gets the challenge to answer.
   */
  signIn: (username: string, password: string) => Promise<LoginResult>;
  /** Second step: the challenge token and a code from the authenticator. */
  completeMfa: (challengeToken: string, code: string) => Promise<LoginResult>;
  /** Re-read the current user, after enrolling an authenticator for instance. */
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();

  const userQuery = useQuery({
    queryKey: ['auth', 'me'],
    queryFn: async () => {
      try {
        return await api.get<CurrentUser>('/auth/me');
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) return null;
        throw error;
      }
    },
    retry: false,
    staleTime: 60_000,
  });

  const methodsQuery = useQuery({
    queryKey: ['auth', 'methods'],
    queryFn: () => api.get<AuthMethods>('/auth/methods'),
    staleTime: 300_000,
  });

  const signInMutation = useMutation({
    mutationFn: (payload: { username: string; password: string }) =>
      api.post<LoginResult>('/auth/login', payload),
    onSuccess: (result) => {
      // The endpoint answers a LoginResult, not a user. Storing the envelope
      // as the current user is what left `permissions` undefined.
      if (result.user) queryClient.setQueryData(['auth', 'me'], result.user);
    },
  });

  const mfaMutation = useMutation({
    // This endpoint answers a LoginResult too, with the user nested in it.
    mutationFn: (payload: { challenge_token: string; code: string }) =>
      api.post<LoginResult>('/auth/login/mfa', payload),
    onSuccess: (result) => {
      if (result.user) queryClient.setQueryData(['auth', 'me'], result.user);
    },
  });

  const signOutMutation = useMutation({
    mutationFn: () => api.post<{ message: string }>('/auth/logout'),
    onSuccess: () => {
      queryClient.setQueryData(['auth', 'me'], null);
      queryClient.clear();
    },
  });

  const value = useMemo<AuthState>(() => {
    const user = userQuery.data ?? null;
    return {
      user,
      methods: methodsQuery.data ?? null,
      loading: userQuery.isLoading,
      // `permissions` is optional-chained as well: a payload that lost it must
      // deny access, not crash the whole interface.
      can: (permission) => Boolean(user?.permissions?.includes(permission)),
      signIn: async (username, password) =>
        signInMutation.mutateAsync({ username, password }),
      completeMfa: async (challengeToken, code) =>
        mfaMutation.mutateAsync({ challenge_token: challengeToken, code }),
      refresh: async () => {
        await queryClient.invalidateQueries({ queryKey: ['auth', 'me'] });
      },
      signOut: async () => {
        await signOutMutation.mutateAsync();
      },
    };
  }, [
    userQuery.data,
    userQuery.isLoading,
    methodsQuery.data,
    signInMutation,
    mfaMutation,
    signOutMutation,
    queryClient,
  ]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside an AuthProvider');
  return context;
}
