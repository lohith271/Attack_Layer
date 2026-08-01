import { useState, useEffect, useCallback } from "react";
import { 
    getHitlQueue, 
    approveHitlRequest, 
    rejectHitlRequest, 
    getResolvedHitlItems,
    getPendingIps,
    getResolvedIps,
    approveIpBlock,
    rejectIpBlock
} from "../api/attacklayer";
import "../styles/hitl.css";

let toastId = 0;

function useToasts() {
    const [toasts, setToasts] = useState([]);
    const addToast = useCallback((message, type = "info") => {
        const id = ++toastId;
        setToasts((prev) => [...prev, { id, message, type }]);
        setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 3500);
    }, []);
    return { toasts, addToast };
}

function getSeverityClass(sev) {
    if (!sev) return "severity-low";
    const s = sev.toLowerCase();
    if (s === "critical") return "severity-critical";
    if (s === "high") return "severity-high";
    if (s === "medium") return "severity-medium";
    return "severity-low";
}

function HITLCard({ request, onApprove, onReject }) {
    const [busy, setBusy] = useState(false);

    async function handleApprove() {
        setBusy(true);
        await onApprove(request.id);
        setBusy(false);
    }

    async function handleReject() {
        setBusy(true);
        await onReject(request.id);
        setBusy(false);
    }

    const isMemory = request.memory_id != null;

    return (
        <div className="hitl-card">
            {/* Header */}
            <div className="hitl-card-header">
                <div>
                    <div className="hitl-card-id">{isMemory ? `Memory Item #${request.memory_id}` : `Request #${request.id}`}</div>
                    <div className="hitl-card-tags">
                        {request.threat_type && (
                            <span className="hitl-tag threat">
                                {request.threat_type}
                            </span>
                        )}
                        <span className={`hitl-tag ${getSeverityClass(request.severity)}`}>
                            {request.severity || "LOW"}
                        </span>
                        <span className="hitl-tag status-pending">⏳ Pending Review</span>
                    </div>
                </div>
                <div className="hitl-timestamp">{request.timestamp}</div>
            </div>

            {/* Body */}
            <div className="hitl-card-body">
                <div className="hitl-field">
                    <div className="hitl-field-label">{isMemory ? "Memory Fact / Contaminated Content" : "User Prompt"}</div>
                    <div className="hitl-field-value prompt-text">{request.prompt}</div>
                </div>
                <div className="hitl-field">
                    <div className="hitl-field-label">Detection Reason</div>
                    <div className="hitl-field-value reason-text">
                        {request.detection_reason || "Automated threat detection flagged this request."}
                    </div>
                </div>
            </div>

            {/* Actions */}
            <div className="hitl-card-footer">
                <button className="approve-btn" onClick={handleApprove} disabled={busy}>
                    <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
                    {isMemory ? "Approve & Save (Yes)" : "Approve & Execute (Yes)"}
                </button>
                <button className="reject-btn" onClick={handleReject} disabled={busy}>
                    <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    {isMemory ? "Reject & Delete (No)" : "Reject & Block (No)"}
                </button>
            </div>
        </div>
    );
}

function IPHITLCard({ item, onApprove, onReject }) {
    const [busy, setBusy] = useState(false);

    async function handleApprove() {
        setBusy(true);
        await onApprove(item.ip_address);
        setBusy(false);
    }

    async function handleReject() {
        setBusy(true);
        await onReject(item.ip_address);
        setBusy(false);
    }

    return (
        <div className="hitl-card" style={{ borderColor: "var(--color-warning)" }}>
            <div className="hitl-card-header">
                <div>
                    <div className="hitl-card-id">🌐 Target IP: {item.ip_address}</div>
                    <div className="hitl-card-tags">
                        <span className="hitl-tag threat">EXCESSIVE_BLOCKS</span>
                        <span className="hitl-tag severity-high">HIGH RISK</span>
                        <span className="hitl-tag status-pending">⏳ Pending IP Block Approval</span>
                    </div>
                </div>
                <div className="hitl-timestamp">{item.timestamp}</div>
            </div>

            <div className="hitl-card-body">
                <div className="hitl-field">
                    <div className="hitl-field-label">Target IP Address</div>
                    <div className="hitl-field-value prompt-text">{item.ip_address}</div>
                </div>
                <div className="hitl-field">
                    <div className="hitl-field-label">Detection Reason</div>
                    <div className="hitl-field-value reason-text">
                        {item.detection_reason}
                    </div>
                </div>
                <div className="hitl-field">
                    <div className="hitl-field-label">Interaction Metrics</div>
                    <div className="hitl-field-value reason-text">
                        Total Requests: <strong>{item.total_interactions}</strong> | Blocked: <strong>{item.block_count} ({item.block_rate_pct}%)</strong>
                    </div>
                </div>
            </div>

            <div className="hitl-card-footer">
                <button className="reject-btn" style={{ background: "#ef4444" }} onClick={handleApprove} disabled={busy}>
                    🚫 Approve & Block IP
                </button>
                <button className="approve-btn" style={{ background: "#10b981" }} onClick={handleReject} disabled={busy}>
                    ✅ Reject Block & Allow IP
                </button>
            </div>
        </div>
    );
}


function HITLPage() {
    const [queue, setQueue] = useState([]);
    const [ipQueue, setIpQueue] = useState([]);
    const [loading, setLoading] = useState(true);
    const [approved, setApproved] = useState(0);
    const [rejected, setRejected] = useState(0);
    const [answeredItems, setAnsweredItems] = useState([]);
    const [resolvedIps, setResolvedIps] = useState([]);
    const [activeTab, setActiveTab] = useState("prompts");
    const [manualIp, setManualIp] = useState("");
    const { toasts, addToast } = useToasts();

    const loadQueue = useCallback(async () => {
        try {
            const [queueData, resolvedData, pendingIpsData, resolvedIpsData] = await Promise.all([
                getHitlQueue(),
                getResolvedHitlItems(),
                getPendingIps(),
                getResolvedIps(),
            ]);
            setQueue(queueData || []);
            setAnsweredItems(resolvedData || []);
            setIpQueue(pendingIpsData || []);
            setResolvedIps(resolvedIpsData || []);
            setApproved((resolvedData || []).filter((r) => r.status === "approved").length);
            setRejected((resolvedData || []).filter((r) => r.status === "rejected").length);
        } catch {
            addToast("Failed to load HITL queue", "error");
        } finally {
            setLoading(false);
        }
    }, [addToast]);

    useEffect(() => {
        loadQueue();
        const timer = setInterval(loadQueue, 5000);
        return () => clearInterval(timer);
    }, [loadQueue]);

    async function handleManualIpBlock(e) {
        if (e) e.preventDefault();
        const trimmed = manualIp.trim();
        if (!trimmed) {
            addToast("Please enter a valid IP address to block", "error");
            return;
        }
        try {
            await approveIpBlock(trimmed);
            setApproved((n) => n + 1);
            setManualIp("");
            addToast(`🚫 IP ${trimmed} manually BLOCKED by human reviewer`, "success");
            loadQueue();
        } catch {
            addToast("Failed to manually block IP", "error");
        }
    }


    async function handleApprove(id) {
        try {
            const req = queue.find((r) => r.id === id);
            const res = await approveHitlRequest(id);
            setQueue((prev) => prev.filter((r) => r.id !== id));
            setApproved((n) => n + 1);
            setAnsweredItems((prev) => [
                {
                    id,
                    prompt: req?.prompt,
                    status: "approved",
                    response: res.response || "(no response returned)",
                    memory_id: req?.memory_id,
                },
                ...prev,
            ]);
            addToast("✓ Request approved", "success");
        } catch {
            addToast("Failed to approve request", "error");
        }
    }

    async function handleReject(id) {
        try {
            const req = queue.find((r) => r.id === id);
            await rejectHitlRequest(id);
            setQueue((prev) => prev.filter((r) => r.id !== id));
            setRejected((n) => n + 1);
            setAnsweredItems((prev) => [
                {
                    id,
                    prompt: req?.prompt,
                    status: "rejected",
                    response: req?.memory_id ? "Memory permanently deleted." : "Request rejected and blocked by security policy.",
                    memory_id: req?.memory_id,
                },
                ...prev,
            ]);
            addToast("✕ Request rejected", "error");
        } catch {
            addToast("Failed to reject request", "error");
        }
    }

    async function handleApproveIp(ipAddress) {
        try {
            await approveIpBlock(ipAddress);
            setIpQueue((prev) => prev.filter((item) => item.ip_address !== ipAddress));
            setApproved((n) => n + 1);
            addToast(`🚫 IP ${ipAddress} approved and BLOCKED`, "success");
            loadQueue();
        } catch {
            addToast("Failed to approve IP block", "error");
        }
    }

    async function handleRejectIp(ipAddress) {
        try {
            await rejectIpBlock(ipAddress);
            setIpQueue((prev) => prev.filter((item) => item.ip_address !== ipAddress));
            setRejected((n) => n + 1);
            addToast(`✅ IP ${ipAddress} unblocked (marked Trusted)`, "info");
            loadQueue();
        } catch {
            addToast("Failed to reject IP block", "error");
        }
    }

    if (loading) {
        return (
            <div className="loading-state">
                <div className="spinner" />
                Loading Human Validation Queue…
            </div>
        );
    }

    const promptQueue = queue.filter(req => req.memory_id == null);
    const memoryQueue = queue.filter(req => req.memory_id != null);
    
    const activeQueue = activeTab === "prompts" ? promptQueue : activeTab === "memories" ? memoryQueue : ipQueue;
    
    const resolvedPrompts = answeredItems.filter(item => item.memory_id == null);
    const resolvedMemories = answeredItems.filter(item => item.memory_id != null);
    const activeResolved = activeTab === "prompts" ? resolvedPrompts : activeTab === "memories" ? resolvedMemories : resolvedIps;

    const totalPendingCount = queue.length + ipQueue.length;

    return (
        <>
            <div className="page-header">
                <h1 className="page-title">Human Validation Center</h1>
                <p className="page-subtitle">
                    Review flagged requests, memory scans, and IP address block requests requiring human approval
                </p>
            </div>

            {/* Summary stats */}
            <div className="hitl-stats-row">
                <div className="hitl-stat-card">
                    <div className="hitl-stat-value" style={{ color: "var(--color-warning)" }}>
                        {totalPendingCount}
                    </div>
                    <div className="hitl-stat-label">Total Pending Reviews</div>
                </div>
                <div className="hitl-stat-card">
                    <div className="hitl-stat-value" style={{ color: "var(--color-success)" }}>
                        {approved}
                    </div>
                    <div className="hitl-stat-label">Approved This Session</div>
                </div>
                <div className="hitl-stat-card">
                    <div className="hitl-stat-value" style={{ color: "var(--color-danger)" }}>
                        {rejected}
                    </div>
                    <div className="hitl-stat-label">Rejected This Session</div>
                </div>
            </div>

            {/* Tabs */}
            <div className="hitl-tabs-container">
                <button 
                    className={`hitl-tab-btn ${activeTab === "prompts" ? "active" : ""}`}
                    onClick={() => setActiveTab("prompts")}
                >
                    Prompts & Chat Requests ({promptQueue.length})
                </button>
                <button 
                    className={`hitl-tab-btn ${activeTab === "memories" ? "active" : ""}`}
                    onClick={() => setActiveTab("memories")}
                >
                    Memory Scans ({memoryQueue.length})
                </button>
                <button 
                    className={`hitl-tab-btn ${activeTab === "ips" ? "active" : ""}`}
                    onClick={() => setActiveTab("ips")}
                >
                    🌐 IP Address Approvals ({ipQueue.length})
                </button>
            </div>

            {/* Manual IP Block Control Bar */}
            {activeTab === "ips" && (
                <div style={{
                    background: "#ffffff",
                    padding: "18px 24px",
                    borderRadius: "10px",
                    border: "1px solid #e2e8f0",
                    boxShadow: "0 1px 3px rgba(0, 0, 0, 0.05)",
                    marginBottom: "24px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "16px",
                    flexWrap: "wrap"
                }}>
                    <div>
                        <h4 style={{ margin: "0 0 4px 0", fontSize: "15px", fontWeight: "700", color: "#1e293b" }}>
                            ⚡ Instant Manual IP Block
                        </h4>
                        <p style={{ margin: 0, fontSize: "13px", color: "var(--color-text-muted, #64748b)" }}>
                            Human reviewers can manually block any IP address at any time, instantly preventing all chat requests & memory storage.
                        </p>
                    </div>
                    <form onSubmit={handleManualIpBlock} style={{ display: "flex", gap: "10px" }}>
                        <input 
                            type="text" 
                            placeholder="Enter IP Address (e.g. 192.168.1.100)"
                            value={manualIp}
                            onChange={(e) => setManualIp(e.target.value)}
                            style={{
                                padding: "9px 14px",
                                borderRadius: "6px",
                                border: "1px solid #cbd5e1",
                                background: "#ffffff",
                                color: "#0f172a",
                                fontSize: "13px",
                                width: "260px",
                                outline: "none"
                            }}
                        />
                        <button
                            type="submit"
                            style={{
                                padding: "9px 18px",
                                borderRadius: "6px",
                                background: "#ef4444",
                                color: "#ffffff",
                                border: "none",
                                fontWeight: "600",
                                fontSize: "13px",
                                cursor: "pointer",
                                boxShadow: "0 1px 2px rgba(239, 68, 68, 0.2)"
                            }}
                        >
                            🚫 Block IP Now
                        </button>
                    </form>
                </div>
            )}


            {/* Queue header */}
            <div className="hitl-queue-header">
                <div className="hitl-queue-title">
                    Pending {activeTab === "prompts" ? "Prompts" : activeTab === "memories" ? "Memory Scans" : "IP Address Block Approvals"}
                    {activeQueue.length > 0 && (
                        <span className="hitl-count-badge">{activeQueue.length}</span>
                    )}
                </div>
                <button className="hitl-refresh-btn" onClick={loadQueue}>
                    <svg viewBox="0 0 24 24">
                        <polyline points="23 4 23 10 17 10"/>
                        <path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/>
                    </svg>
                    Refresh
                </button>
            </div>


            {/* Queue */}
            {activeQueue.length === 0 ? (
                <div className="hitl-empty">
                    <div className="hitl-empty-icon">
                        <svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
                    </div>
                    <h3>Queue is Clear</h3>
                    <p>All pending {activeTab === "prompts" ? "prompts" : activeTab === "memories" ? "memory scans" : "IP block reviews"} have been processed. No pending human review required.</p>
                </div>
            ) : (
                <div className="hitl-queue">
                    {activeTab === "ips" ? (
                        activeQueue.map((item) => (
                            <IPHITLCard
                                key={item.id || item.ip_address}
                                item={item}
                                onApprove={handleApproveIp}
                                onReject={handleRejectIp}
                            />
                        ))
                    ) : (
                        activeQueue.map((req) => (
                            <HITLCard
                                key={req.id}
                                request={req}
                                onApprove={handleApprove}
                                onReject={handleReject}
                            />
                        ))
                    )}
                </div>
            )}

            {/* Resolved Items */}
            {activeResolved.length > 0 && (
                <div style={{ marginTop: "2rem" }}>
                    <div className="hitl-queue-header">
                        <div className="hitl-queue-title">
                            Resolved {activeTab === "prompts" ? "Prompts" : activeTab === "memories" ? "Memory Scans" : "IP Block Decisions"}
                        </div>
                    </div>
                    <div className="hitl-queue">
                        {activeResolved.map((item) => (
                            <div key={item.id} className="hitl-card" style={{ opacity: 0.9 }}>
                                <div className="hitl-card-header">
                                    <div>
                                        <div className="hitl-card-id">
                                            {item.ip_address ? `IP Address: ${item.ip_address}` : item.memory_id ? `Memory Item #${item.memory_id}` : `Request #${item.id}`}
                                        </div>
                                        <div className="hitl-card-tags">
                                            <span className={`hitl-tag ${item.status === "approved" ? "severity-low" : "severity-critical"}`}>
                                                {item.status === "approved" ? (item.ip_address ? "🚫 Block Approved" : "✓ Approved") : (item.ip_address ? "✅ Block Rejected (Allowed)" : "✕ Rejected")}
                                            </span>
                                        </div>
                                    </div>
                                    <div className="hitl-timestamp">{item.timestamp}</div>
                                </div>
                                <div className="hitl-card-body">
                                    {item.prompt && (
                                        <div className="hitl-field">
                                            <div className="hitl-field-label">{item.memory_id ? "Memory Fact" : "User Prompt"}</div>
                                            <div className="hitl-field-value prompt-text">{item.prompt}</div>
                                        </div>
                                    )}
                                    {item.ip_address && (
                                        <div className="hitl-field">
                                            <div className="hitl-field-label">Target IP Address</div>
                                            <div className="hitl-field-value prompt-text">{item.ip_address}</div>
                                        </div>
                                    )}
                                    <div className="hitl-field">
                                        <div className="hitl-field-label">
                                            {item.status === "approved" ? (item.ip_address ? "IP Security Action" : item.memory_id ? "Memory Status" : "AI Response") : "Security Action"}
                                        </div>
                                        <div className="hitl-field-value reason-text">{item.response}</div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Toasts */}
            <div className="hitl-toast-area">
                {toasts.map((t) => (
                    <div key={t.id} className={`hitl-toast ${t.type}`}>
                        {t.message}
                    </div>
                ))}
            </div>
        </>
    );
}

export default HITLPage;