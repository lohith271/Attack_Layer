import { useState, useEffect } from "react";
import {
    getAllMemories,
    clearEpisodicMemory,
    clearShortTermMemory,
    clearLongTermMemory,
    deleteMemory,
    archiveMemory,
    getMemoryHistory,
    getMemoryTrust,
    refreshMemory,
    refreshMemoryType,
} from "../api/attacklayer";
import "../styles/memory-vault.css";

function MemoryItem({ mem, onRefresh, setNotification }) {
    const [detail, setDetail] = useState(null);
    const [refreshing, setRefreshing] = useState(false);
    const trust = mem.trust_score || 0;
    const trustClass =
        trust >= 0.7 ? "trust-high" : trust >= 0.4 ? "trust-mid" : "trust-low";

    async function handleDelete() {
        if (!window.confirm("Delete this memory permanently?")) return;
        await deleteMemory(mem.id);
        onRefresh();
    }

    async function handleArchive() {
        await archiveMemory(mem.id);
        onRefresh();
    }

    async function handleHistory() {
        const history = await getMemoryHistory(mem.id);
        setDetail({ type: "history", data: history });
    }

    async function handleTrust() {
        const trustData = await getMemoryTrust(mem.id);
        setDetail({ type: "trust", data: trustData });
    }

    async function handleRefreshItem() {
        setRefreshing(true);
        try {
            const res = await refreshMemory(mem.id);
            if (res.status === "sent_to_approval") {
                setNotification({
                    type: "warning",
                    title: "Attack Detected & Deactivated!",
                    message: `Memory item was re-scanned, classified as a security threat (${res.attack_type}). It has been removed from active memory and sent to the Human Validation Center for review.`
                });
                onRefresh();
            } else if (res.status === "removed") {
                setNotification({
                    type: "danger",
                    title: "Attack Detected & Removed!",
                    message: `Memory item was re-scanned, classified as a security threat (${res.attack_type}), and has been permanently deleted from storage.`
                });
                onRefresh();
            } else {
                setNotification({
                    type: "success",
                    title: "Memory Fact Cleared Safe",
                    message: `Verified safe! Fact: "${res.fact}". No attacks detected (Security Class: ${res.attack_type}).`
                });
                onRefresh();
            }
        } catch (err) {
            console.error(err);
            setNotification({
                type: "danger",
                title: "Scan Failed",
                message: "An error occurred while re-evaluating the memory record."
            });
        } finally {
            setRefreshing(false);
        }
    }

    return (
        <div className="memory-item">
            <div className="memory-item-fact">{mem.fact || "—"}</div>
            <div className="memory-item-meta">
                <span className={`memory-meta-chip ${trustClass}`}>
                    Trust: {trust.toFixed(2)}
                </span>
                {mem.category && (
                    <span className="memory-meta-chip">{mem.category}</span>
                )}
                {mem.memory_type && (
                    <span className="memory-meta-chip">{mem.memory_type}</span>
                )}
                {mem.source && (
                    <span className="memory-meta-chip">{mem.source}</span>
                )}
                <span className="memory-meta-chip">
                    {new Date(mem.updated_at || mem.created_at || Date.now()).toLocaleDateString()}
                </span>
            </div>
            <div className="memory-item-meta" style={{ marginTop: 6 }}>
                <button className="clear-btn" style={{ padding: "4px 8px", fontSize: 11, background: "var(--color-primary-bg)", color: "var(--color-primary)", border: "1px solid var(--color-primary-bg-hover)" }} onClick={handleTrust}>Trust</button>
                <button className="clear-btn" style={{ padding: "4px 8px", fontSize: 11, background: "var(--color-primary-bg)", color: "var(--color-primary)", border: "1px solid var(--color-primary-bg-hover)" }} onClick={handleHistory}>History</button>
                <button className="clear-btn" style={{ padding: "4px 8px", fontSize: 11, background: "var(--color-primary-bg)", color: "var(--color-primary)", border: "1px solid var(--color-primary-bg-hover)" }} onClick={handleArchive}>Archive</button>
                <button className="clear-btn" style={{ padding: "4px 8px", fontSize: 11, background: "var(--color-danger-bg)", color: "var(--color-danger)", border: "1px solid var(--color-danger-border)" }} onClick={handleDelete}>Delete</button>
                <button 
                    className={`clear-btn refresh-item-btn ${refreshing ? "spin-icon" : ""}`} 
                    style={{ padding: "4px 8px", fontSize: 11, background: "var(--color-success-bg)", color: "var(--color-success)", border: "1px solid var(--color-success-border)", marginLeft: "auto" }} 
                    onClick={handleRefreshItem}
                    disabled={refreshing}
                >
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: 10, height: 10, marginRight: 3 }}>
                        <path d="M23 4v6h-6"/>
                        <path d="M1 20v-6h6"/>
                        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                    </svg>
                    {refreshing ? "Scanning…" : "Refresh"}
                </button>
            </div>
            {detail && (
                <div className="memory-item-meta" style={{ marginTop: 8, fontSize: 12 }}>
                    {detail.type === "trust" && (
                        <span>{detail.data.trust_explanation?.summary || `Trust: ${detail.data.trust_score}`}</span>
                    )}
                    {detail.type === "history" && (
                        <span>{detail.data.length} version(s) — latest: {detail.data[0]?.new_fact || mem.fact}</span>
                    )}
                    <button className="clear-btn" style={{ padding: "2px 6px", fontSize: 10, marginLeft: 8 }} onClick={() => setDetail(null)}>Close</button>
                </div>
            )}
        </div>
    );
}

function MemoryPanel({ type, title, desc, memories, onClear, onRefresh, onRefreshType, setNotification, accentClass, icon }) {
    const [confirming, setConfirming] = useState(false);
    const [clearing, setClearing] = useState(false);
    const [scanning, setScanning] = useState(false);

    async function doConfirmClear() {
        setClearing(true);
        await onClear();
        setConfirming(false);
        setClearing(false);
    }

    async function handleScan() {
        setScanning(true);
        try {
            await onRefreshType();
        } finally {
            setScanning(false);
        }
    }

    return (
        <>
            <div className={`memory-panel ${accentClass}`}>
                {/* Header */}
                <div className="memory-panel-header">
                    <div className="panel-title-row">
                        <div className="panel-title">
                            {icon}
                            {title}
                        </div>
                        <span className="panel-count-badge">{memories.length}</span>
                    </div>
                    <div className="panel-desc">{desc}</div>
                </div>

                {/* Body */}
                <div className="memory-panel-body">
                    {memories.length === 0 ? (
                        <div className="panel-empty">
                            <div className="panel-empty-icon">📭</div>
                            <p>No {title.toLowerCase()} stored</p>
                        </div>
                    ) : (
                        memories.map((mem, i) => (
                            <MemoryItem key={mem.id || i} mem={mem} onRefresh={onRefresh} setNotification={setNotification} />
                        ))
                    )}
                </div>

                {/* Footer */}
                <div className="memory-panel-footer">
                    <span className="panel-footer-info">
                        {memories.length} {memories.length === 1 ? "entry" : "entries"}
                    </span>
                    <div style={{ display: "flex", gap: "6px" }}>
                        <button
                            className={`clear-btn refresh-panel-btn ${scanning ? "spin-icon" : ""}`}
                            disabled={memories.length === 0 || scanning}
                            onClick={handleScan}
                            style={{ background: "var(--color-primary-bg)", color: "var(--color-primary)", border: "1px solid var(--color-primary-bg-hover)" }}
                        >
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ width: 12, height: 12 }}>
                                <path d="M23 4v6h-6"/>
                                <path d="M1 20v-6h6"/>
                                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                            </svg>
                            {scanning ? "Scanning…" : "Scan & Refresh"}
                        </button>
                        <button
                            className="clear-btn"
                            disabled={memories.length === 0 || scanning}
                            onClick={() => setConfirming(true)}
                        >
                            <svg viewBox="0 0 24 24">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6l-1 14H6L5 6"/>
                                <path d="M10 11v6M14 11v6"/>
                            </svg>
                            Clear
                        </button>
                    </div>
                </div>
            </div>

            {/* Confirm dialog */}
            {confirming && (
                <div className="confirm-overlay" onClick={() => setConfirming(false)}>
                    <div className="confirm-dialog" onClick={(e) => e.stopPropagation()}>
                        <h3>Clear {title}?</h3>
                        <p>
                            This will permanently delete all {memories.length}{" "}
                            {title.toLowerCase()} entries. This action cannot be undone.
                        </p>
                        <div className="confirm-actions">
                            <button className="confirm-cancel-btn" onClick={() => setConfirming(false)}>
                                Cancel
                            </button>
                            <button
                                className="confirm-clear-btn"
                                onClick={doConfirmClear}
                                disabled={clearing}
                            >
                                {clearing ? "Clearing…" : "Yes, Clear"}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}

function MemoryVaultPage() {
    const [episodic, setEpisodic] = useState(() => {
        try { return JSON.parse(localStorage.getItem("attacklayer_mem_episodic") || "[]"); } catch { return []; }
    });
    const [shortTerm, setShortTerm] = useState(() => {
        try { return JSON.parse(localStorage.getItem("attacklayer_mem_shortterm") || "[]"); } catch { return []; }
    });
    const [longTerm, setLongTerm] = useState(() => {
        try { return JSON.parse(localStorage.getItem("attacklayer_mem_longterm") || "[]"); } catch { return []; }
    });
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [notification, setNotification] = useState(null);

    useEffect(() => {
        load();
        const timer = setInterval(load, 8000);
        return () => clearInterval(timer);
    }, []);

    async function load() {
        try {
            const all = await getAllMemories();
            const activeMemories = all.filter(m => m.status === "ACTIVE");
            const ep = activeMemories.filter(
                (m) =>
                    m.memory_type === "EPISODIC" ||
                    (
                        m.source &&
                        m.source.toLowerCase().includes("session")
                    )
            );
            const st = activeMemories.filter(
                (m) =>
                    m.memory_type === "SHORT_TERM" ||
                    (
                        m.importance_score != null &&
                        m.importance_score < 0.5 &&
                        !ep.includes(m)
                    )
            );
            const lt = activeMemories.filter(
                (m) =>
                    m.memory_type === "LONG_TERM" ||
                    (
                        m.trust_score > 0.7 &&
                        m.importance_score >= 0.5 &&
                        !ep.includes(m) &&
                        !st.includes(m)
                    )
            );

            let finalEp, finalSt, finalLt;
            if (ep.length === 0 && st.length === 0 && lt.length === 0 && activeMemories.length > 0) {
                const t = Math.ceil(activeMemories.length / 3);
                finalEp = activeMemories.slice(0, t);
                finalSt = activeMemories.slice(t, 2 * t);
                finalLt = activeMemories.slice(2 * t);
            } else {
                finalEp = ep; finalSt = st; finalLt = lt;
            }
            setEpisodic(finalEp);
            setShortTerm(finalSt);
            setLongTerm(finalLt);
            localStorage.setItem("attacklayer_mem_episodic", JSON.stringify(finalEp));
            localStorage.setItem("attacklayer_mem_shortterm", JSON.stringify(finalSt));
            localStorage.setItem("attacklayer_mem_longterm", JSON.stringify(finalLt));
            setError("");
        } catch {
            const hasCached = localStorage.getItem("attacklayer_mem_episodic");
            if (!hasCached) setError("Failed to load memories.");
        } finally {
            setLoading(false);
        }
    }

    async function handleRefreshType(type) {
        try {
            const res = await refreshMemoryType(type);
            if (res.status === "success") {
                const displayType = type.split("-").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
                if (res.removed_count > 0) {
                    setNotification({
                        type: "warning",
                        title: `${res.removed_count} Attack(s) Blocked & Deactivated!`,
                        message: `Completed scan of ${res.total_checked} memories in ${displayType}. Detected ${res.removed_count} attack(s), which have been removed from active memory and sent to the Human Validation Center for review.`
                    });
                } else {
                    setNotification({
                        type: "success",
                        title: "Security Scan Completed",
                        message: `Scanned all ${res.total_checked} memories in ${displayType}. All records are safe.`
                    });
                }
                await load();
            }
        } catch (err) {
            console.error(err);
            setNotification({
                type: "danger",
                title: "Scan Failed",
                message: `Failed to complete security scan for ${type} memory.`
            });
        }
    }

    if (loading) {
        return (
            <div className="loading-state">
                <div className="spinner" />
                Loading Memory Vault…
            </div>
        );
    }

    return (
        <>
            <div className="page-header">
                <h1 className="page-title">Memory Vault</h1>
                <p className="page-subtitle">
                    Manage and monitor the AI agent's memory systems — episodic, short-term, and long-term storage
                </p>
            </div>

            {notification && (
                <div className={`scan-notification notification-${notification.type}`}>
                    <div style={{ flex: 1 }}>
                        <h4 className="notification-title">{notification.title}</h4>
                        <p className="notification-msg">{notification.message}</p>
                    </div>
                    <button className="notification-close-btn" onClick={() => setNotification(null)}>×</button>
                </div>
            )}

            {error && (
                <div style={{ marginBottom: 20, padding: "12px 16px", background: "var(--color-danger-bg)", border: "1px solid var(--color-danger-border)", borderRadius: "var(--radius-md)", color: "var(--color-danger)", fontSize: 13 }}>
                    {error}
                </div>
            )}

            <div className="memory-panels">
                <MemoryPanel
                    type="episodic"
                    accentClass="episodic"
                    title="Episodic Memory"
                    desc="Session-specific memories · Temporary context"
                    memories={episodic}
                    onRefresh={load}
                    onRefreshType={() => handleRefreshType("episodic")}
                    setNotification={setNotification}
                    onClear={async () => {
                        try { await clearEpisodicMemory(); setEpisodic([]); } catch { setError("Failed to clear episodic memory."); }
                    }}
                    icon={
                        <svg viewBox="0 0 24 24">
                            <circle cx="12" cy="12" r="10"/>
                            <polyline points="12 6 12 12 16 14"/>
                        </svg>
                    }
                />
                <MemoryPanel
                    type="short-term"
                    accentClass="short-term"
                    title="Short-Term Memory"
                    desc="Recent interactions · Active conversation memory"
                    memories={shortTerm}
                    onRefresh={load}
                    onRefreshType={() => handleRefreshType("short-term")}
                    setNotification={setNotification}
                    onClear={async () => {
                        try { await clearShortTermMemory(); setShortTerm([]); } catch { setError("Failed to clear short-term memory."); }
                    }}
                    icon={
                        <svg viewBox="0 0 24 24">
                            <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/>
                        </svg>
                    }
                />
                <MemoryPanel
                    type="long-term"
                    accentClass="long-term"
                    title="Long-Term Memory"
                    desc="Persistent knowledge · Stored trusted information"
                    memories={longTerm}
                    onRefresh={load}
                    onRefreshType={() => handleRefreshType("long-term")}
                    setNotification={setNotification}
                    onClear={async () => {
                        try { await clearLongTermMemory(); setLongTerm([]); } catch { setError("Failed to clear long-term memory."); }
                    }}
                    icon={
                        <svg viewBox="0 0 24 24">
                            <ellipse cx="12" cy="5" rx="9" ry="3"/>
                            <path d="M3 5v14a9 3 0 0018 0V5"/>
                            <path d="M3 12a9 3 0 0018 0"/>
                        </svg>
                    }
                />
            </div>
        </>
    );
}

export default MemoryVaultPage;