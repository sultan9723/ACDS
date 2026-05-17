import React, { createContext, useContext, useState, useEffect } from "react";
import {
  loginUser,
  verifyToken,
  getUserProfile,
  logoutUser,
  setUnauthorizedHandler,
  clearStoredAuth,
} from "../utils/api";

const AuthContext = createContext(null);
const DEMO_TOKEN = "demo-local-token";
const DEMO_USER = {
  email: "admin@acds.com",
  name: "Demo Admin",
  role: "admin",
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const clearAuthState = () => {
    clearStoredAuth();
    setToken(null);
    setUser(null);
  };

  const [user, setUser] = useState(null);
  const [token, setToken] = useState(
    localStorage.getItem("authToken") || localStorage.getItem("token")
  );
  const [isLoading, setIsLoading] = useState(true);

  // Check if user is authenticated on mount
  useEffect(() => {
    const initializeAuth = async () => {
      const storedToken =
        localStorage.getItem("authToken") || localStorage.getItem("token");
      const storedUser =
        localStorage.getItem("authUser") || localStorage.getItem("user");

      if (!storedToken || !storedUser) {
        setIsLoading(false);
        return;
      }

      if (storedToken === DEMO_TOKEN) {
        const resolvedUser = JSON.parse(storedUser);
        localStorage.setItem("authToken", DEMO_TOKEN);
        localStorage.setItem("authUser", JSON.stringify(resolvedUser));
        setToken(DEMO_TOKEN);
        setUser(resolvedUser);
        setIsLoading(false);
        return;
      }

      try {
        const validation = await verifyToken();
        if (!validation?.valid) {
          clearAuthState();
          setIsLoading(false);
          return;
        }

        const profile = await getUserProfile();
        const resolvedUser = profile?.user || JSON.parse(storedUser);

        localStorage.setItem("authUser", JSON.stringify(resolvedUser));
        setToken(storedToken);
        setUser(resolvedUser);
      } catch {
        clearAuthState();
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearAuthState();
    });

    return () => {
      setUnauthorizedHandler(null);
    };
  }, []);

  const login = async (email, password) => {
    try {
      const data = await loginUser(email, password);
      const accessToken = data?.access_token || data?.token;
      const responseUser = data?.user;

      if (!accessToken || !responseUser) {
        return { success: false, error: data?.message || "Invalid credentials" };
      }

      localStorage.setItem("authToken", accessToken);
      localStorage.setItem("authUser", JSON.stringify(responseUser));

      setToken(accessToken);
      setUser(responseUser);

      return { success: true };
    } catch (error) {
      return { success: false, error: error.detail || error.message || "Login failed" };
    }
  };

  const enableDemoMode = () => {
    localStorage.setItem("authToken", DEMO_TOKEN);
    localStorage.setItem("authUser", JSON.stringify(DEMO_USER));
    setToken(DEMO_TOKEN);
    setUser(DEMO_USER);
  };

  const logout = async () => {
    try {
      await logoutUser();
    } catch {
      // no-op: always clear local state on logout
    }
    clearAuthState();
  };

  const isAuthenticated = !!token && !!user;

  const value = {
    user,
    token,
    isLoading,
    isAuthenticated,
    login,
    enableDemoMode,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export default AuthContext;
