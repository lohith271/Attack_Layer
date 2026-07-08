import { useState, useEffect, useCallback } from "react";
import { getHitlQueue, approveHitlRequest, rejectHitlRequest, getResolvedHitlItems } from "../api/attacklayer";
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

function HITLPage() {
    const [queue, setQueue] = useState([]);
    const [loading, setLoading] = useState(true);
    const [approved, setApproved] = useState(0);
    const [rejected, setRejected] = useState(0);
    const [answeredItems, setAnsweredItems] = useState([]);
    const [activeTab, setActiveTab] = useState("prompts");
    const { toasts, addToast } = useToasts();

    const loadQueue = useCallback(async () => {
        try {
            const [queueData, resolvedData] = await Promise.all([
                getHitlQueue(),
                getResolvedHitlItems(),
            ]);
            setQueue(queueData);
            setAnsweredItems(resolvedData);
            setApproved(resolvedData.filter((r) => r.status === "approved").length);
            setRejected(resolvedData.filter((r) => r.status === "rejected").length);
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
    const activeQueue = activeTab === "prompts" ? promptQueue : memoryQueue;
    
    const resolvedPrompts = answeredItems.filter(item => item.memory_id == null);
    const resolvedMemories = answeredItems.filter(item => item.memory_id != null);
    const activeResolved = activeTab === "prompts" ? resolvedPrompts : resolvedMemories;

    return (
        <>
            <div className="page-header">
                <h1 className="page-title">Human Validation Center</h1>
                <p className="page-subtitle">
                    Review flagged requests that require human approval before the AI responds
                </p>
            </div>

            {/* Summary stats */}
            <div className="hitl-stats-row">
                <div className="hitl-stat-card">
                    <div className="hitl-stat-value" style={{ color: "var(--color-warning)" }}>
                        {queue.length}
                    </div>
                    <div className="hitl-stat-label">Pending Review</div>
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
            </div>

            {/* Queue header */}
            <div className="hitl-queue-header">
                <div className="hitl-queue-title">
                    Pending {activeTab === "prompts" ? "Prompts" : "Memory Scans"}
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
                    <p>All pending {activeTab === "prompts" ? "prompts" : "memory scans"} have been processed. No pending human review required.</p>
                </div>
            ) : (
                <div className="hitl-queue">
                    {activeQueue.map((req) => (
                        <HITLCard
                            key={req.id}
                            request={req}
                            onApprove={handleApprove}
                            onReject={handleReject}
                        />
                    ))}
                </div>
            )}

            {/* Resolved Items */}
            {activeResolved.length > 0 && (
                <div style={{ marginTop: "2rem" }}>
                    <div className="hitl-queue-header">
                        <div className="hitl-queue-title">Resolved {activeTab === "prompts" ? "Prompts" : "Memory Scans"}</div>
                    </div>
                    <div className="hitl-queue">
                        {activeResolved.map((item) => (
                            <div key={item.id} className="hitl-card" style={{ opacity: 0.9 }}>
                                <div className="hitl-card-header">
                                    <div>
                                        <div className="hitl-card-id">{item.memory_id ? `Memory Item #${item.memory_id}` : `Request #${item.id}`}</div>
                                        <div className="hitl-card-tags">
                                            <span className={`hitl-tag ${item.status === "approved" ? "severity-low" : "severity-critical"}`}>
                                                {item.status === "approved" ? "✓ Approved" : "✕ Rejected"}
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
                                    <div className="hitl-field">
                                        <div className="hitl-field-label">
                                            {item.status === "approved" ? (item.memory_id ? "Memory Status" : "AI Response") : "Security Action"}
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