import { useState, useEffect } from "react";
import { getAuditEvents, getMemoryRefreshStats } from "../api/attacklayer";
import { useNavigate } from "react-router-dom";
import "../styles/dashboard.css";

function DecisionBadge({ decision }) {
    const d = (decision || "").toUpperCase();
    const cls =
        d === "ALLOW"
            ? "decision-allow"
            : d === "BLOCK"
            ? "decision-block"
            : "decision-allow_with_warning";
    return <span className={cls}>{decision || "—"}</span>;
}

const KPI_CONFIG = [
    {
        key: "allow", label: "Allowed Requests", variant: "allow",
        iconClass: "allow-icon",
        icon: <svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>,
    },
    {
        key: "block", label: "Blocked Attacks", variant: "block",
        iconClass: "block-icon",
        icon: <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>,
    },
    {
        key: "warning", label: "Flagged (Warning)", variant: "warning",
        iconClass: "warning-icon",
        icon: <svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    },
    {
        key: "approved", label: "Human Approved", variant: "approved",
        iconClass: "approved-icon",
        icon: <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>,
    },
    {
        key: "rejected", label: "Human Rejected", variant: "rejected",
        iconClass: "rejected-icon",
        icon: <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>,
    },
];

const moduleCards = [
    {
        to: "/memory-vault",
        label: "Memory Vault",
        desc: "Manage episodic, short-term, and long-term AI memory systems",
        icon: (
            <svg viewBox="0 0 24 24">
                <ellipse cx="12" cy="5" rx="9" ry="3"/>
                <path d="M3 5v14a9 3 0 0018 0V5"/>
                <path d="M3 12a9 3 0 0018 0"/>
            </svg>
        ),
    },
    {
        to: "/hitl",
        label: "Human Validation Center",
        desc: "Review and approve flagged requests requiring human intervention",
        icon: (
            <svg viewBox="0 0 24 24">
                <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
                <circle cx="9" cy="7" r="4"/>
                <path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
            </svg>
        ),
    },
    {
        to: "/threat-analysis",
        label: "Threat Analysis",
        desc: "Analytics, charts, and IP intelligence for security incidents",
        icon: (
            <svg viewBox="0 0 24 24">
                <line x1="18" y1="20" x2="18" y2="10"/>
                <line x1="12" y1="20" x2="12" y2="4"/>
                <line x1="6" y1="20" x2="6" y2="14"/>
            </svg>
        ),
    },
];

function DashboardPage() {
    const navigate = useNavigate();
    const [events, setEvents] = useState(() => {
        try {
            const cached = localStorage.getItem("attacklayer_dashboard_events");
            return cached ? JSON.parse(cached) : [];
        } catch { return []; }
    });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [refreshStats, setRefreshStats] = useState({
        refreshes_today: 0,
        detected_today: 0,
        pending_reviews_count: 0
    });

    useEffect(() => {
        load();
        const timer = setInterval(load, 10000);
        return () => clearInterval(timer);
    }, []);

    async function load() {
        try {
            const data = await getAuditEvents();
            setEvents(data);
            localStorage.setItem("attacklayer_dashboard_events", JSON.stringify(data));
            
            try {
                const stats = await getMemoryRefreshStats();
                setRefreshStats(stats);
            } catch (statsErr) {
                console.error("Failed to load memory refresh stats:", statsErr);
            }
            
            setError("");
        } catch {
            // Backend down — keep showing cached data, just show a soft warning
            const cached = localStorage.getItem("attacklayer_dashboard_events");
            if (!cached) setError("Backend offline. No cached data available.");
            // If cache exists, events state already has it — no error shown
        } finally {
            setLoading(false);
        }
    }

    function exportToExcel(eventList = events, filenamePrefix = "attacklayer_audit") {
        if (!eventList.length) return;
        const headers = ["ID", "Time", "Prompt", "Decision", "Threat Type", "Risk Score", "Execution Time (ms)", "Quarantine Status", "Conflict Status"];
        const rows = eventList.map(e => [
            e.id,
            `"${e.time || new Date(e.timestamp || Date.now()).toLocaleTimeString()}"`,
            `"${(e.prompt || "").replace(/"/g, '""')}"`,
            `"${e.final_decision || ""}"`,
            `"${e.threat || ""}"`,
            e.risk_score || 0,
            e.execution_time_ms || 0,
            `"${e.quarantine_status || ""}"`,
            `"${e.conflict_status || ""}"`
        ]);
        
        const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `${filenamePrefix}_${new Date().toISOString().split('T')[0]}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    // Derive KPI values
    const kpiValues = {
        allow: events.filter((e) => e.final_decision === "ALLOW").length,
        block: events.filter((e) => e.final_decision === "BLOCK").length,
        warning: events.filter((e) => e.final_decision === "ALLOW_WITH_WARNING").length,
        approved: events.filter((e) => e.explanation?.human_decision === "APPROVED").length,
        rejected: events.filter((e) => e.explanation?.human_decision === "REJECTED").length,
    };

    // Filter events into chat prompts vs memory checking
    const chatEvents = events.filter(
        (e) => e.operation !== "REFRESH_ACTION" && e.operation !== "REFRESH_SCAN"
    );
    const memoryEvents = events.filter(
        (e) => e.operation === "REFRESH_ACTION" || e.operation === "REFRESH_SCAN"
    );

    if (loading) {
        return (
            <div className="dashboard-loading">
                <div className="spinner" />
                Loading Security Dashboard…
            </div>
        );
    }

    return (
        <>
            {/* Page header */}
            <div className="page-header">
                <h1 className="page-title">AI Security Operations Center</h1>
                <p className="page-subtitle">
                    Real-time threat monitoring and security analytics · Auto-refreshes every 10s
                </p>
            </div>

            {error && (
                <div style={{ marginBottom: 20, padding: "12px 16px", background: "var(--color-danger-bg)", border: "1px solid var(--color-danger-border)", borderRadius: "var(--radius-md)", color: "var(--color-danger)", fontSize: 13 }}>
                    {error}
                </div>
            )}

            {/* KPI Cards */}
            <div className="kpi-grid">
                {KPI_CONFIG.map((cfg) => (
                    <div key={cfg.key} className={`kpi-card ${cfg.variant}`}>
                        <div className={`kpi-icon ${cfg.iconClass}`}>
                            {cfg.icon}
                        </div>
                        <div className="kpi-value">{kpiValues[cfg.key]}</div>
                        <div className="kpi-label">{cfg.label}</div>
                    </div>
                ))}
            </div>



            {/* Audit Logs */}
            <div className="audit-section">
                <div className="audit-section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                        <h2 style={{ margin: 0 }}>Recent Audit Logs</h2>
                        <div className="live-badge">
                            <span className="live-dot" />
                            Live
                        </div>
                    </div>
                    <button onClick={() => exportToExcel(chatEvents, "attacklayer_chat_audit")} style={{ padding: '6px 12px', background: 'white', border: '1px solid var(--color-border)', borderRadius: '4px', cursor: 'pointer', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-text)' }}>
                        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        Export to Excel (CSV)
                    </button>
                </div>
                <div className="audit-table-wrap">
                    <table className="audit-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Prompt</th>
                                <th>Decision</th>
                                <th>Threat Type</th>
                                <th>Risk Score</th>
                                <th>Execution Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {chatEvents.slice(0, 10).map((event) => (
                                <tr key={event.id}>
                                    <td style={{ whiteSpace: "nowrap", color: "var(--color-text-muted)", fontSize: 12 }}>
                                        {event.time || new Date(event.timestamp || Date.now()).toLocaleTimeString()}
                                    </td>
                                    <td>
                                        <div className="audit-prompt" title={event.prompt}>
                                            {event.prompt || "—"}
                                        </div>
                                    </td>
                                    <td>
                                        <DecisionBadge decision={event.final_decision} />
                                    </td>
                                    <td style={{ fontSize: 12, color: "var(--color-text-secondary)" }}>
                                        {event.threat || "—"}
                                    </td>
                                    <td className="audit-risk" style={{ color: event.risk_score > 0.7 ? "var(--color-danger)" : event.risk_score > 0.4 ? "var(--color-warning)" : "var(--color-success)" }}>
                                        {(event.risk_score || 0).toFixed(2)}
                                    </td>
                                    <td style={{ fontSize: 12, color: "var(--color-text-muted)" }}>
                                        {event.execution_time_ms ? `${event.execution_time_ms}ms` : "—"}
                                    </td>
                                </tr>
                            ))}
                            {chatEvents.length === 0 && (
                                <tr>
                                    <td colSpan={6} style={{ textAlign: "center", color: "var(--color-text-muted)", padding: "32px 16px" }}>
                                        No audit events recorded yet
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Memory Scan & Approval Summary */}
            <div className="audit-section" style={{ marginTop: '2rem' }}>
                <div className="audit-section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                        <h2 style={{ margin: 0 }}>Memory Security Scan Summary</h2>
                        <div className="live-badge" style={{ backgroundColor: 'var(--color-primary-bg)', color: 'var(--color-primary)' }}>
                            <span className="live-dot" style={{ backgroundColor: 'var(--color-primary)' }} />
                            Active
                        </div>
                    </div>
                </div>

                <div className="kpi-grid" style={{ marginTop: '20px' }}>
                    <div className="kpi-card" style={{ padding: '20px', marginBottom: 0 }}>
                        <div className="kpi-value">{refreshStats.refreshes_today}</div>
                        <div className="kpi-label">Refreshes Happened Today</div>
                    </div>
                    <div className="kpi-card block" style={{ padding: '20px', marginBottom: 0 }}>
                        <div className="kpi-value" style={{ color: 'var(--color-danger)' }}>{refreshStats.detected_today}</div>
                        <div className="kpi-label">Detected Attacks Today</div>
                    </div>
                    <div className="kpi-card warning" style={{ padding: '20px', marginBottom: 0 }}>
                        <div className="kpi-value" style={{ color: 'var(--color-warning)' }}>{refreshStats.pending_reviews_count}</div>
                        <div className="kpi-label">Memories Waiting Human Approval</div>
                    </div>
                </div>
            </div>

            {/* Memory Audit Logs */}
            <div className="audit-section" style={{ marginTop: '2rem' }}>
                <div className="audit-section-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                        <h2 style={{ margin: 0 }}>Memory Security Scan & Refresh Logs</h2>
                        <div className="live-badge">
                            <span className="live-dot" />
                            Live
                        </div>
                    </div>
                    <button onClick={() => exportToExcel(memoryEvents, "attacklayer_memory_audit")} style={{ padding: '6px 12px', background: 'white', border: '1px solid var(--color-border)', borderRadius: '4px', cursor: 'pointer', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-text)' }}>
                        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        Export to Excel (CSV)
                    </button>
                </div>
                <div className="audit-table-wrap">
                    <table className="audit-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Memory / Prompt</th>
                                <th>Decision</th>
                                <th>Threat Type</th>
                                <th>Risk Score</th>
                                <th>Execution Time</th>
                            </tr>
                        </thead>
                        <tbody>
                            {memoryEvents.slice(0, 10).map((event) => (
                                <tr key={event.id}>
                                    <td style={{ whiteSpace: "nowrap", color: "var(--color-text-muted)", fontSize: 12 }}>
                                        {event.time || new Date(event.timestamp || Date.now()).toLocaleTimeString()}
                                    </td>
                                    <td>
                                        <div className="audit-prompt" title={event.prompt}>
                                            {event.prompt || "—"}
                                        </div>
                                    </td>
                                    <td>
                                        <DecisionBadge decision={event.final_decision} />
                                    </td>
                                    <td style={{ fontSize: 12, color: "var(--color-text-secondary)" }}>
                                        {event.threat || "—"}
                                    </td>
                                    <td className="audit-risk" style={{ color: event.risk_score > 0.7 ? "var(--color-danger)" : event.risk_score > 0.4 ? "var(--color-warning)" : "var(--color-success)" }}>
                                        {(event.risk_score || 0).toFixed(2)}
                                    </td>
                                    <td style={{ fontSize: 12, color: "var(--color-text-muted)" }}>
                                        {event.execution_time_ms ? `${event.execution_time_ms}ms` : "—"}
                                    </td>
                                </tr>
                            ))}
                            {memoryEvents.length === 0 && (
                                <tr>
                                    <td colSpan={6} style={{ textAlign: "center", color: "var(--color-text-muted)", padding: "32px 16px" }}>
                                        No memory scan/refresh events recorded yet
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </>
    );
}

export default DashboardPage;