import { NavLink } from "react-router-dom";

const links = [
  { to: "/analyze", label: "Analyze" },
  { to: "/history", label: "History" },
  { to: "/dashboard", label: "Dashboard" },
  { to: "/privacy", label: "Privacy" },
];

export default function NavBar() {
  return (
    <nav aria-label="Main">
      {links.map((link) => (
        <NavLink key={link.to} to={link.to}>
          {link.label}
        </NavLink>
      ))}
    </nav>
  );
}
