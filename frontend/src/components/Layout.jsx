import { Link, useLocation } from "react-router-dom";
import { useState, useEffect, useRef } from "react";
import { getAuditEvents } from "../api/attacklayer";
import "./layout.css";

const navItems = [
    {
        to: "/dashboard",
        label: "Security Operations Center",
        icon: (
            <svg viewBox="0 0 24 24">
                <rect x="3" y="3" width="7" height="7" rx="1" />
                <rect x="14" y="3" width="7" height="7" rx="1" />
                <rect x="3" y="14" width="7" height="7" rx="1" />
                <rect x="14" y="14" width="7" height="7" rx="1" />
            </svg>
        ),
    },
    {
        to: "/memory-vault",
        label: "Memory Vault",
        icon: (
            <svg viewBox="0 0 24 24">
                <ellipse cx="12" cy="5" rx="9" ry="3" />
                <path d="M3 5v14a9 3 0 0018 0V5" />
                <path d="M3 12a9 3 0 0018 0" />
            </svg>
        ),
    },
    {
        to: "/hitl",
        label: "Human Review Center",
        icon: (
            <svg viewBox="0 0 24 24">
                <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75" />
            </svg>
        ),
    },
    {
        to: "/threat-analysis",
        label: "Threat Analysis & Intelligence",
        icon: (
            <svg viewBox="0 0 24 24">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
        ),
    },
    {
        to: "/model-performance",
        label: "Model Performance",
        icon: (
            <svg viewBox="0 0 24 24">
                <path d="M21.21 15.89A10 10 0 1 1 8 2.83" />
                <path d="M22 12A10 10 0 0 0 12 2v10z" />
            </svg>
        ),
    },
    {
        to: "/agent-investigator",
        label: "Agent Investigator",
        icon: (
            <svg viewBox="0 0 24 24">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 16v-4" />
                <path d="M12 8h.01" />
            </svg>
        ),
    },
];

function Layout({ children }) {
    const location = useLocation();
    const [attackAlert, setAttackAlert] = useState(null);
    const lastEventId = useRef(null);

    useEffect(() => {
        let isMounted = true;
        async function checkAttacks() {
            try {
                const events = await getAuditEvents();
                if (events && events.length > 0) {
                    const latest = events[0];
                    if (lastEventId.current && latest.id !== lastEventId.current) {
                        if (latest.final_decision === "BLOCK" || latest.final_decision === "ALLOW_WITH_WARNING") {
                            if (isMounted) {
                                setAttackAlert({
                                    id: latest.id,
                                    type: latest.threat || latest.attack_type || "Unknown Threat",
                                    decision: latest.final_decision
                                });
                                setTimeout(() => setAttackAlert(null), 5000);
                            }
                        }
                    }
                    if (isMounted) lastEventId.current = latest.id;
                }
            } catch (err) {
                // Ignore silent poll errors
            }
        }
        checkAttacks();
        const interval = setInterval(checkAttacks, 5000);
        return () => {
            isMounted = false;
            clearInterval(interval);
        };
    }, []);

    return (
        <div className="app-layout">
            {/* Sidebar */}
            <aside className="app-sidebar">
                {/* Brand */}
                <div className="sidebar-brand">
                    <div className="sidebar-brand-icon">
                        <svg viewBox="0 0 24 24">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                    </div>
                    <div className="sidebar-brand-text">
                        <span className="sidebar-brand-name">AttackLayer</span>
                        <span className="sidebar-brand-sub">AI-SOC Platform</span>
                    </div>
                </div>

                {/* Nav */}
                <nav className="sidebar-nav">
                    <span className="sidebar-section-label">Operations</span>
                    {navItems.map((item) => (
                        <Link
                            key={item.to}
                            to={item.to}
                            className={
                                location.pathname === item.to
                                    ? "nav-link active"
                                    : "nav-link"
                            }
                        >
                            {item.icon}
                            {item.label}
                        </Link>
                    ))}
                </nav>

                {/* Footer */}
                <div className="sidebar-footer">
                    <Link to="/chat" className="sidebar-back-btn">
                        <svg viewBox="0 0 24 24">
                            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
                        </svg>
                        Back to Chat
                    </Link>
                </div>
            </aside>

            {/* Main content */}
            <main className="app-content">
                {children}
            </main>

            {/* Global Attack Alert */}
            {attackAlert && (
                <div style={{
                    position: 'fixed', top: 20, right: 20, zIndex: 9999,
                    background: attackAlert.decision === "BLOCK" ? 'var(--color-danger-bg)' : 'var(--color-warning-bg)',
                    border: `1px solid ${attackAlert.decision === "BLOCK" ? 'var(--color-danger-border)' : 'var(--color-warning-border)'}`,
                    color: attackAlert.decision === "BLOCK" ? 'var(--color-danger)' : 'var(--color-warning)',
                    padding: '16px', borderRadius: '8px', boxShadow: '0 10px 25px rgba(0,0,0,0.1)',
                    display: 'flex', alignItems: 'center', gap: '12px'
                }}>
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <div>
                        <div style={{ fontWeight: 600, fontSize: '14px' }}>
                            {attackAlert.decision === "BLOCK" ? "Threat Blocked" : "Threat Flagged"}
                        </div>
                        <div style={{ fontSize: '12px', opacity: 0.9, textTransform: "capitalize" }}>
                            {attackAlert.type.toLowerCase().replace(/_/g, ' ')} detected
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default Layout;