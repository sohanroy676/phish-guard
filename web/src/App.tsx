import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth";
import NavBar from "./components/NavBar";
import Analyze from "./pages/Analyze";
import AnalyzeEmail from "./pages/AnalyzeEmail";
import Login from "./pages/Login";
import Placeholder from "./pages/Placeholder";
import Register from "./pages/Register";

function RequireLogin({ children }: { children: ReactNode }) {
  const { email } = useAuth();
  if (email === undefined) return <p>Loading…</p>;
  if (email === null) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <>
      <NavBar />
      <main>
        <Routes>
          <Route path="/" element={<Navigate to="/analyze" replace />} />
          <Route
            path="/analyze"
            element={
              <RequireLogin>
                <Analyze />
              </RequireLogin>
            }
          />
          <Route
            path="/analyze/email"
            element={
              <RequireLogin>
                <AnalyzeEmail />
              </RequireLogin>
            }
          />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/history" element={<Placeholder title="History" />} />
          <Route path="/dashboard" element={<Placeholder title="Dashboard" />} />
          <Route path="/privacy" element={<Placeholder title="Privacy" />} />
          <Route path="*" element={<Placeholder title="Not found" />} />
        </Routes>
      </main>
    </>
  );
}
