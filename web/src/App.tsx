import { Navigate, Route, Routes } from "react-router-dom";
import NavBar from "./components/NavBar";
import Placeholder from "./pages/Placeholder";

export default function App() {
  return (
    <>
      <NavBar />
      <main>
        <Routes>
          <Route path="/" element={<Navigate to="/analyze" replace />} />
          <Route path="/analyze" element={<Placeholder title="Analyze" />} />
          <Route path="/history" element={<Placeholder title="History" />} />
          <Route path="/dashboard" element={<Placeholder title="Dashboard" />} />
          <Route path="/privacy" element={<Placeholder title="Privacy" />} />
          <Route path="*" element={<Placeholder title="Not found" />} />
        </Routes>
      </main>
    </>
  );
}
