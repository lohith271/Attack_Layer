import { useState, useRef, useEffect } from "react";
import {
    sendChatMessage,
    getHitlStatus
} from "../api/attacklayer";
import { useNavigate } from "react-router-dom";
import "../styles/chat.css";
import {
    bootstrapChatState,
    createSession,
    updateSession,
    deleteSession as deleteSessionStorage,
    titleFromMessage,
    createSessionId,
} from "../utils/chatSessions";

const suggestions = [
    "What security threats do you protect against?",
    "Explain memory poisoning attacks",
    "What is prompt injection?",
    "How does HITL validation work?",
];

const formatTime = (time) => {
    if (!time) return "--:--";

    const date = new Date(time);

    if (isNaN(date.getTime())) return "--:--";

    return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
    });
};

function MessageBubble({ message }) {
    const isUser = message.role === "user";
    return (
        <div className={`message-row ${isUser ? "user-row" : ""}`}>
            {/* Avatar */}
            <div className={`message-avatar ${isUser ? "user-avatar" : "assistant-avatar"}`}>
                {isUser ? (
                    "U"
                ) : (
                    <svg viewBox="0 0 24 24">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    </svg>
                )}
            </div>
            {/* Bubble */}
            <div className="message-content">
                <div className={`message-bubble ${isUser ? "user-bubble" : "assistant-bubble"}`}>
                    {message.content}
                </div>
                <span className="message-time">{formatTime(message.time)}</span>
            </div>
        </div>
    );
}

function ChatPage() {
    const navigate = useNavigate();
    const [sessions, setSessions] = useState(() => {
        const state = bootstrapChatState();
        return state.sessions;
    });
    const [activeId, setActiveId] = useState(() => {
        const state = bootstrapChatState();
        return state.activeId;
    });
    const [input, setInput] = useState("");
    const [loading, setLoading] = useState(false);
    const messagesEndRef = useRef(null);

    const activeSession = sessions.find((s) => s.id === activeId) || sessions[0];
    const messages = activeSession?.messages || [];

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages, loading, activeId]);

    const [pendingHitlIds, setPendingHitlIds] = useState(() =>
        JSON.parse(localStorage.getItem("pendingHitl") || "[]")
    );

    useEffect(() => {
        if (pendingHitlIds.length === 0) return;
        const intervals = [];

        pendingHitlIds.forEach(({ reqId, sessionId }) => {
            const poll = setInterval(async () => {
                try {
                    const status = await getHitlStatus(reqId);
                    if (status.resolved) {
                        clearInterval(poll);
                        const current = JSON.parse(localStorage.getItem("pendingHitl") || "[]");
                        const updated = current.filter((p) => p.reqId !== reqId);
                        localStorage.setItem("pendingHitl", JSON.stringify(updated));
                        setPendingHitlIds(updated);

                        const followUp = {
                            role: "assistant",
                            content: status.response,
                            time: new Date().toISOString(),
                        };
                        setSessions((prev) =>
                            prev.map((s) => {
                                if (s.id !== sessionId) return s;
                                const updatedMsgs = [...s.messages, followUp];
                                updateSession(s.id, { messages: updatedMsgs });
                                return { ...s, messages: updatedMsgs };
                            })
                        );
                    }
                } catch {
                    clearInterval(poll);
                }
            }, 3000);
            intervals.push(poll);
        });

        return () => intervals.forEach(clearInterval);
    }, [pendingHitlIds]);


    function handleNewChat() {
            const session = createSession();
            setSessions((prev) => [session, ...prev]);
            setActiveId(session.id);
        }
    function handleDeleteSession(id) {
            const remaining = deleteSessionStorage(id);
            if (remaining.length === 0) {
                const fresh = createSession();
                setSessions([fresh]);
                setActiveId(fresh.id);
            } else {
                setSessions(remaining);
                if (activeId === id) {
                    setActiveId(remaining[0].id);
                }
            }
        }

    async function send(text) {
        const msg = (text || input).trim();
        if (!msg || loading) return;
        setInput("");
        setLoading(true);

        const userMsg = {
    role: "user",
    content: msg,
    time: new Date().toISOString(),
};

        setSessions((prev) =>
            prev.map((s) => {
                if (s.id !== activeId) return s;
                const updatedMsgs = [...s.messages, userMsg];
                const newTitle = s.messages.length === 0 ? titleFromMessage(msg) : s.title;
                updateSession(s.id, { messages: updatedMsgs, title: newTitle });
                return {
                    ...s,
                    title: newTitle,
                    messages: updatedMsgs,
                };
            })
        );
        try {
            const res = await sendChatMessage(activeId, msg);
            const aiMsg = {
                role: "assistant",
                content: res.response || (res.hitl_request_id
                    ? `⏳ This request requires human approval (Request #${res.hitl_request_id}). The response will appear here once approved.`
                    : res.message || "I couldn't process that request."),
                time: new Date().toISOString(),
            };
            setSessions((prev) =>
                prev.map((s) => {
                    if (s.id !== activeId) return s;
                    const updatedMsgs = [...s.messages, aiMsg];
                    updateSession(s.id, { messages: updatedMsgs });
                    return { ...s, messages: updatedMsgs };
                })
            );
            if (res.hitl_request_id) {
                const pending = JSON.parse(localStorage.getItem("pendingHitl") || "[]");
                const newEntry = { reqId: res.hitl_request_id, sessionId: activeId };
                const updated = [...pending, newEntry];
                localStorage.setItem("pendingHitl", JSON.stringify(updated));
                setPendingHitlIds(updated);
            }
        }
        
        catch {
            const errMsg = {
                role: "assistant",
                content: "Sorry, something went wrong. Please try again.",
                time: new Date().toISOString(),
            };
            setSessions((prev) =>
                prev.map((s) => {
                    if (s.id !== activeId) return s;
                    const updatedMsgs = [...s.messages, errMsg];
                    updateSession(s.id, { messages: updatedMsgs });
                    return { ...s, messages: updatedMsgs };
                })
            );
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="chat-page">
            {/* === LEFT SIDEBAR === */}
            <aside className="chat-sidebar">
                {/* Brand */}
                <div className="chat-sidebar-header">
                    <div className="chat-brand-icon">
                        <svg viewBox="0 0 24 24">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                    </div>
                    <div className="chat-brand-text">
                        <div className="chat-brand-name">AttackLayer</div>
                        <div className="chat-brand-sub">AI-SOC</div>
                    </div>
                </div>

                {/* New chat */}
                <div className="chat-sidebar-actions">
                    <button className="new-chat-btn" onClick={handleNewChat}>
                        <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                        New Chat
                    </button>
                </div>

                {/* History */}
                <span className="chat-history-label">History</span>
                <div className="chat-history-list">
                    {sessions.map((s) => (
                        <div
                            key={s.id}
                            className={`chat-history-item ${s.id === activeId ? "active" : ""}`}
                            onClick={() => setActiveId(s.id)}
                        >
                            <svg viewBox="0 0 24 24">
                                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
                            </svg>
                            <span className="chat-history-text">{s.title}</span>
                            <button
                                className="chat-history-delete"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    handleDeleteSession(s.id);
                                }}
                                title="Delete"
                            >
                                ×
                            </button>
                        </div>
                    ))}
                </div>

                {/* Footer */}
                <div className="chat-sidebar-footer">
                    <button
                        className="dashboard-sidebar-btn"
                        onClick={() => navigate("/dashboard")}
                    >
                        <svg viewBox="0 0 24 24">
                            <rect x="3" y="3" width="7" height="7" rx="1"/>
                            <rect x="14" y="3" width="7" height="7" rx="1"/>
                            <rect x="3" y="14" width="7" height="7" rx="1"/>
                            <rect x="14" y="14" width="7" height="7" rx="1"/>
                        </svg>
                        Open Dashboard
                    </button>
                </div>
            </aside>

            {/* === MAIN AREA === */}
            <div className="chat-main">
                {/* Top bar */}
                <div className="chat-topbar">
                    <div>
                        <div className="chat-topbar-title">AttackLayer AI-SOC</div>
                        <div className="chat-topbar-meta">Secured by threat detection pipeline</div>
                    </div>
                </div>

                {/* Messages */}
                <div className="chat-messages">
                    {messages.length === 0 && !loading ? (
                        <div className="chat-welcome">
                            <div className="chat-welcome-icon">
                                <svg viewBox="0 0 24 24">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                </svg>
                            </div>
                            <h2>How can I help you today?</h2>
                            <p>
                                Powered by AttackLayer's AI Security Operations Center. All messages are scanned for threats before processing.
                            </p>
                            <div className="chat-suggestions">
                                {suggestions.map((s, i) => (
                                    <button
                                        key={i}
                                        className="suggestion-chip"
                                        onClick={() => send(s)}
                                    >
                                        {s}
                                    </button>
                                ))}
                            </div>
                        </div>
                    ) : (
                        <>
                            {messages.map((msg, i) => (
                                <MessageBubble key={i} message={msg} />
                            ))}
                            {loading && (
                                <div className="typing-row">
                                    <div className="message-avatar assistant-avatar">
                                        <svg viewBox="0 0 24 24">
                                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                                        </svg>
                                    </div>
                                    <div className="typing-indicator">
                                        <span className="typing-dot" />
                                        <span className="typing-dot" />
                                        <span className="typing-dot" />
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                    <div ref={messagesEndRef} />
                </div>

                {/* Input */}
                <div className="chat-input-wrapper">
                    <div className="chat-input-box">
                        <input
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            placeholder="Message AttackLayer AI..."
                            onKeyDown={(e) => {
                                if (e.key === "Enter" && !e.shiftKey) {
                                    e.preventDefault();
                                    send();
                                }
                            }}
                            disabled={loading}
                        />
                        <button
                            className="chat-send-btn"
                            onClick={() => send()}
                            disabled={loading || !input.trim()}
                        >
                            <svg viewBox="0 0 24 24">
                                <line x1="22" y1="2" x2="11" y2="13"/>
                                <polygon points="22 2 15 22 11 13 2 9 22 2"/>
                            </svg>
                        </button>
                    </div>
                    <p className="chat-input-hint">
                        AttackLayer monitors all requests for threats in real-time
                    </p>
                </div>
            </div>
        </div>
    );
}

export default ChatPage;
