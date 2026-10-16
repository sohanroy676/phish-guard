import { Link, NavLink } from "react-router-dom";
import { useAuth } from "../auth";

const links = [
  { to: "/analyze", label: "Analyze" },
  { to: "/history", label: "History" },
  { to: "/dashboard", label: "Dashboard" },
  { to: "/privacy", label: "Privacy" },
];

export default function NavBar() {
  const { email, logout } = useAuth();
  return (
    <header>
      <nav aria-label="Main">
        {links.map((link) => (
          <NavLink key={link.to} to={link.to}>
            {link.label}
          </NavLink>
        ))}
      </nav>
      <div className="account">
        {email ? (
          <>
            <span>{email}</span>
            <button type="button" onClick={() => void logout()}>
              Log out
            </button>
          </>
        ) : email === null ? (
          <>
            <Link to="/login">Log in</Link>
            <Link to="/register">Register</Link>
          </>
        ) : null}
      </div>
    </header>
  );
}
