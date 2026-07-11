import { useState, useEffect, useRef } from "react";
import { queryAgentInvestigator } from "../api/attacklayer";
import "../styles/dashboard.css";

const INITIAL_GREETING = {
    sender: "agent",
    text: "Hello! I am the Threat Analytics Agent. I work alongside the Risk Scoring Agent, Policy Agent, and Memory Agent.\n\nYou can ask me questions about today's security activity. For example:\n- 'What blocking happened today?'\n- 'Show me warning logs' or 'quarantined items'",
};

function AgentInvestigatorPage() {
    const [messages, setMessages] = useState(() => {
        try {
            const cached = localStorage.getItem("agent_investigator_messages");
            return cached ? JSON.parse(cached) : [INITIAL_GREETING];
        } catch {
            return [INITIAL_GREETING];
        }
    });
    const [input, setInput] = useState("");
    const [loading, setLoading] = useState(false);
    const messagesEndRef = useRef(null);

    // Persist messages to localStorage
    useEffect(() => {
        try {
            localStorage.setItem("agent_investigator_messages", JSON.stringify(messages));
        } catch (err) {
            console.error("Failed to persist agent messages", err);
        }
    }, [messages]);

    // Scroll to bottom on new messages
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages, loading]);

    function handleDownloadReport(text, reportDate) {
        const filename = `Security_Today_Report_${reportDate || new Date().toISOString().split('T')[0]}.md`;
        const blob = new Blob([text], { type: "text/markdown;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.setAttribute("download", filename);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }

    async function handleSend(e) {
        e.preventDefault();
        const queryText = input.trim();
        if (!queryText) return;

        // Append user message
        const newMsgList = [...messages, { sender: "user", text: queryText }];
        setMessages(newMsgList);
        setInput("");
        setLoading(true);

        try {
            const data = await queryAgentInvestigator(queryText);
            setMessages((prev) => [
                ...prev,
                {
                    sender: "agent",
                    text: data.response,
                    stats: data.stats,
                    is_today_report: data.is_today_report,
                    report_date: data.report_date,
                },
            ]);
        } catch (err) {
            setMessages((prev) => [
                ...prev,
                {
                    sender: "agent",
                    text: "Error: Failed to communicate with safety agents. Please check if the backend service is running.",
                },
            ]);
        } finally {
            setLoading(false);
        }
    }

    function handleNewChat() {
        if (window.confirm("Are you sure you want to clear this conversation and start a new chat?")) {
            setMessages([INITIAL_GREETING]);
        }
    }

    return (
        <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)" }}>
            {/* Header */}
            <div className="page-header" style={{ marginBottom: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span style={{ fontSize: "28px" }}>🤖</span>
                    <div>
                        <h1 className="page-title" style={{ margin: 0 }}>Agent Intelligence Console</h1>
                        <p className="page-subtitle" style={{ margin: 0 }}>
                            Cooperative Multi-Agent Security Logs & Incident Investigations
                        </p>
                    </div>
                </div>
                <button
                    onClick={handleNewChat}
                    style={{
                        padding: "8px 16px",
                        background: "var(--color-surface)",
                        border: "1px solid var(--color-border)",
                        borderRadius: "var(--radius-sm)",
                        cursor: "pointer",
                        color: "var(--color-text)",
                        fontSize: "12px",
                        fontWeight: "600",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        boxShadow: "var(--shadow-sm)",
                        transition: "all var(--transition-fast)"
                    }}
                    onMouseEnter={(e) => {
                        e.target.style.background = "var(--color-bg)";
                    }}
                    onMouseLeave={(e) => {
                        e.target.style.background = "var(--color-surface)";
                    }}
                >
                    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
                    </svg>
                    New Chat
                </button>
            </div>

            {/* Chat Container */}
            <div
                style={{
                    flex: 1,
                    background: "var(--color-surface)",
                    border: "1px solid var(--color-border)",
                    borderRadius: "var(--radius-md)",
                    display: "flex",
                    flexDirection: "column",
                    overflow: "hidden",
                    boxShadow: "var(--shadow-sm)"
                }}
            >
                {/* Messages List */}
                <div
                    style={{
                        flex: 1,
                        padding: "20px",
                        overflowY: "auto",
                        display: "flex",
                        flexDirection: "column",
                        gap: "16px",
                    }}
                >
                    {messages.map((msg, index) => {
                        const isUser = msg.sender === "user";
                        return (
                            <div
                                key={index}
                                style={{
                                    display: "flex",
                                    justifyContent: isUser ? "flex-end" : "flex-start",
                                    width: "100%",
                                }}
                            >
                                <div
                                    style={{
                                        maxWidth: "75%",
                                        background: isUser ? "var(--color-primary)" : "var(--color-surface-2)",
                                        border: isUser ? "none" : "1px solid var(--color-border)",
                                        borderRadius: "var(--radius-md)",
                                        padding: "16px",
                                        color: isUser ? "white" : "var(--color-text)",
                                        boxShadow: "var(--shadow-sm)",
                                    }}
                                >
                                    {/* Icon / Tag */}
                                    <div
                                        style={{
                                            display: "flex",
                                            alignItems: "center",
                                            gap: "6px",
                                            fontSize: "11px",
                                            fontWeight: "bold",
                                            color: isUser ? "#bfdbfe" : "var(--color-primary-light)",
                                            marginBottom: "8px",
                                        }}
                                    >
                                        <span>{isUser ? "👤 Developer Query" : "🛡️ Security Agents Pipeline"}</span>
                                    </div>

                                    {/* Message Text */}
                                    <div style={{ whiteSpace: "pre-line", fontSize: "14px", lineHeight: "1.6" }}>
                                        {msg.text}
                                    </div>

                                    {/* Download button for today report */}
                                    {!isUser && msg.is_today_report && (
                                        <div style={{ marginTop: "14px", paddingTop: "12px", borderTop: "1px solid var(--color-border)" }}>
                                            <button
                                                onClick={() => handleDownloadReport(msg.text, msg.report_date)}
                                                style={{
                                                    padding: "6px 14px",
                                                    background: "var(--color-primary-bg)",
                                                    border: "1px solid var(--color-primary-light)",
                                                    borderRadius: "var(--radius-sm)",
                                                    color: "var(--color-primary)",
                                                    fontSize: "12px",
                                                    fontWeight: "600",
                                                    cursor: "pointer",
                                                    display: "inline-flex",
                                                    alignItems: "center",
                                                    gap: "6px",
                                                    boxShadow: "var(--shadow-sm)",
                                                    transition: "all var(--transition-fast)"
                                                }}
                                                onMouseEnter={(e) => {
                                                    e.currentTarget.style.background = "var(--color-primary-bg-hover)";
                                                }}
                                                onMouseLeave={(e) => {
                                                    e.currentTarget.style.background = "var(--color-primary-bg)";
                                                }}
                                            >
                                                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>
                                                </svg>
                                                Download Today Report (.md)
                                            </button>
                                        </div>
                                    )}

                                    {/* Agent Stats Section */}
                                    {!isUser && msg.stats && (
                                        <div
                                            style={{
                                                marginTop: "14px",
                                                paddingTop: "12px",
                                                borderTop: "1px solid var(--color-border)",
                                                display: "flex",
                                                flexWrap: "wrap",
                                                gap: "16px",
                                                fontSize: "12px",
                                                color: "var(--color-text-secondary)",
                                            }}
                                        >
                                            <div>Total Audited: <strong>{msg.stats.total}</strong></div>
                                            <div>Allowed: <strong style={{ color: "var(--color-success)" }}>{msg.stats.allowed}</strong></div>
                                            <div>Blocked: <strong style={{ color: "var(--color-danger)" }}>{msg.stats.blocked}</strong></div>
                                            <div>Warnings: <strong style={{ color: "var(--color-warning)" }}>{msg.stats.warnings}</strong></div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        );
                    })}
                    {loading && (
                        <div style={{ display: "flex", justifyContent: "flex-start", width: "100%" }}>
                            <div
                                style={{
                                    maxWidth: "75%",
                                    background: "var(--color-surface-2)",
                                    border: "1px solid var(--color-border)",
                                    borderRadius: "var(--radius-md)",
                                    padding: "16px",
                                    color: "var(--color-text-secondary)",
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "8px",
                                }}
                            >
                                <span className="spinner" style={{ width: "14px", height: "14px", border: "2px solid var(--color-primary-light)", borderTop: "2px solid transparent", borderRadius: "50%", display: "inline-block", animation: "spin 1s linear infinite" }} />
                                <span>Agents are investigating databases and analyzing logs...</span>
                            </div>
                        </div>
                    )}
                    <div ref={messagesEndRef} />
                </div>

                {/* Form Input */}
                <form
                    onSubmit={handleSend}
                    style={{
                        padding: "16px",
                        background: "var(--color-surface-2)",
                        borderTop: "1px solid var(--color-border)",
                        display: "flex",
                        gap: "12px",
                    }}
                >
                    <input
                        type="text"
                        placeholder="Ask the security agents (e.g. 'What blocks happened today?')"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        disabled={loading}
                        style={{
                            flex: 1,
                            padding: "12px 16px",
                            borderRadius: "var(--radius-sm)",
                            border: "1px solid var(--color-border)",
                            background: "var(--color-surface)",
                            color: "var(--color-text)",
                            fontSize: "14px",
                        }}
                    />
                    <button
                        type="submit"
                        disabled={loading}
                        style={{
                            padding: "12px 24px",
                            background: "var(--color-primary-light)",
                            color: "white",
                            border: "none",
                            borderRadius: "var(--radius-sm)",
                            cursor: "pointer",
                            fontSize: "14px",
                            fontWeight: "bold",
                            transition: "background var(--transition-fast)",
                        }}
                        onMouseEnter={(e) => (e.target.style.background = "var(--color-primary-hover)")}
                        onMouseLeave={(e) => (e.target.style.background = "var(--color-primary-light)")}
                    >
                        Send
                    </button>
                </form>
            </div>
            {/* Embedded styles for spin keyframe */}
            <style>{`
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            `}</style>
        </div>
    );
}

export default AgentInvestigatorPage;
