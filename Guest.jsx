import React from "react";
import { useAuth } from "./AuthProvider";

export default function Guest() {
  const { loginGuest } = useAuth();
  return (
    <div>
      <h2>Continue as Guest</h2>
      <button onClick={loginGuest}>Enter</button>
    </div>
  );
}
