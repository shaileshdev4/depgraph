import { Routes, Route } from "react-router-dom";
import Investigate from "./pages/Investigate";

export default function App() {
  return (
    <Routes>
      <Route path="*" element={<Investigate />} />
    </Routes>
  );
}
