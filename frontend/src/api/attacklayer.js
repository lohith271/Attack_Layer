import axios from "axios";

const API = axios.create({
    baseURL: import.meta.env.VITE_API_BASE_URL || `http://${window.location.hostname}:8000`,
});

/* ===== CHAT ===== */
export async function sendChatMessage(userId, message) {
    const response = await API.post("/chat/", null, {
        params: { user_id: userId || "default", message },
    });
    return response.data;
}

/* ===== AUDIT ===== */
export async function getAuditEvents() {
    const response = await API.get("/audit/events");
    return response.data;
}

/* ===== HITL ===== */
export async function getHitlQueue() {
    const response = await API.get("/hitl/queue");
    return response.data;
}
export async function getResolvedHitlItems() {
    const response = await API.get("/hitl/resolved");
    return response.data;
}
export async function approveHitlRequest(requestId) {
    const response = await API.post(`/hitl/approve/${requestId}`);
    return response.data;
}

export async function rejectHitlRequest(requestId) {
    const response = await API.post(`/hitl/reject/${requestId}`);
    return response.data;
}

/* ===== MEMORY ===== */
export async function getAllMemories() {
    const response = await API.get("/memory/all");
    return response.data;
}

export async function deleteMemory(memoryId) {
    const response = await API.delete(`/memory/${memoryId}`);
    return response.data;
}

export async function archiveMemory(memoryId) {
    const response = await API.post(`/memory/archive/${memoryId}`);
    return response.data;
}

export async function getMemoryHistory(memoryId) {
    const response = await API.get(`/memory/history/${memoryId}`);
    return response.data;
}

export async function getMemoryTrust(memoryId) {
    const response = await API.get(`/memory/trust/${memoryId}`);
    return response.data;
}

export async function clearEpisodicMemory() {
    const response = await API.delete("/memory/episodic");
    return response.data;
}

export async function clearShortTermMemory() {
    const response = await API.delete("/memory/short-term");
    return response.data;
}

export async function clearLongTermMemory() {
    const response = await API.delete("/memory/long-term");
    return response.data;
}

export async function refreshMemory(memoryId) {
    const response = await API.post(`/memory/refresh/${memoryId}`);
    return response.data;
}

export async function refreshMemoryType(memoryType) {
    const response = await API.post(`/memory/refresh-type/${memoryType}`);
    return response.data;
}

export const getHitlStatus = async (requestId) => {
    const response = await API.get(`/hitl/status/${requestId}`);
    return response.data;
};

function normalizeAttackStats(raw) {
    return {
        totalRequests: raw.total_requests ?? raw.total_events ?? 0,
        allowedRequests: raw.allowed_events ?? raw.allowed ?? 0,
        blockedAttacks: raw.blocked_events ?? raw.blocked ?? 0,
        allowWithWarning: raw.allow_with_warning ?? 0,
        humanApproved: raw.human_approved ?? 0,
        humanRejected: raw.human_rejected ?? 0,
        promptInjectionAttempts: raw.prompt_injections ?? 0,
        memoryPoisoningAttempts: raw.memory_poisoning ?? 0,
        falseFactInjectionAttempts: raw.false_fact_injections ?? 0,
        attackSuccessRate: raw.attack_success_rate ?? 0,
        defenseEffectiveness: raw.defense_effectiveness ?? 0,
        trustScoreAverage: raw.trust_score_average ?? raw.average_trust_score ?? 0,
        falsePositiveRate: raw.false_positive_rate ?? 0,
        falseNegativeRate: raw.false_negative_rate ?? 0,
        detectionRate: raw.detection_rate ?? 0,
        poisoningSuccessRate: raw.poisoning_success_rate ?? 0,
        memoryContaminationRate: raw.memory_contamination_rate ?? 0,
        recoveryRate: raw.recovery_rate ?? 0,
        attackClassificationAccuracy: raw.attack_classification_accuracy ?? 0,
    };
}

function normalizeMemoryUsage(raw) {
    if (raw.episodic !== undefined) {
        return {
            episodic: raw.episodic ?? 0,
            shortTerm: raw.shortTerm ?? 0,
            longTerm: raw.longTerm ?? 0,
        };
    }
    if (Array.isArray(raw)) {
        const map = Object.fromEntries(raw.map((r) => [r.memory_type, r.count]));
        return {
            episodic: map.EPISODIC ?? 0,
            shortTerm: map.SHORT_TERM ?? 0,
            longTerm: map.LONG_TERM ?? 0,
        };
    }
    return { episodic: 0, shortTerm: 0, longTerm: 0 };
}

function normalizeHumanApproval(raw) {
    if (raw.approved !== undefined) {
        return { approved: raw.approved ?? 0, rejected: raw.rejected ?? 0 };
    }
    if (Array.isArray(raw)) {
        const approved = raw.find((r) => r.action?.toLowerCase().includes("approv"));
        const rejected = raw.find((r) => r.action?.toLowerCase().includes("reject"));
        return {
            approved: approved?.count ?? 0,
            rejected: rejected?.count ?? 0,
        };
    }
    return { approved: 0, rejected: 0 };
}

function normalizeSeverity(raw) {
    if (raw.critical !== undefined) {
        return raw;
    }
    if (Array.isArray(raw)) {
        const map = Object.fromEntries(raw.map((r) => [r.severity?.toLowerCase(), r.count]));
        return {
            critical: map.critical ?? 0,
            high: map.high ?? 0,
            medium: map.medium ?? 0,
            low: map.low ?? 0,
        };
    }
    return { critical: 0, high: 0, medium: 0, low: 0 };
}

/* ===== ATTACK STATISTICS ===== */
export async function getAttackStatistics() {
    const response = await API.get("/audit/attack-statistics");
    return normalizeAttackStats(response.data);
}

/* ===== THREAT ANALYSIS ENDPOINTS ===== */
export async function getAttackTrendOverTime() {
    try {
        const response = await API.get("/audit/attack-trend-over-time");
        return response.data;
    } catch {
        return [];
    }
}

export async function getDecisionDistribution() {
    try {
        const response = await API.get("/audit/decision-distribution");
        return response.data;
    } catch {
        return [];
    }
}

export async function getThreatCategoryDistribution() {
    try {
        const response = await API.get("/audit/threat-category-distribution");
        return response.data;
    } catch {
        return [];
    }
}

export async function getMemoryUsageDistribution() {
    try {
        const response = await API.get("/audit/memory-usage-distribution");
        return normalizeMemoryUsage(response.data);
    } catch {
        return { episodic: 0, shortTerm: 0, longTerm: 0 };
    }
}

export async function getHumanApprovalVsRejection() {
    try {
        const response = await API.get("/audit/human-approval-vs-rejection");
        return normalizeHumanApproval(response.data);
    } catch {
        return { approved: 0, rejected: 0 };
    }
}

export async function getAttackSeverityBreakdown() {
    try {
        const response = await API.get("/audit/attack-severity-breakdown");
        return normalizeSeverity(response.data);
    } catch {
        return { critical: 0, high: 0, medium: 0, low: 0 };
    }
}

export async function getIPIntelligence() {
    try {
        const response = await API.get("/audit/ip-intelligence");
        return response.data;
    } catch {
        return [];
    }
}

export async function getAttackSuccessRate() {
    const response = await API.get("/audit/attack-success-rate");
    return response.data;
}

/* ===== EXISTING ENDPOINTS ===== */
export async function getTopAttackTypes() {
    const response = await API.get("/audit/top-attacks");
    return response.data;
}

export async function getRiskDistribution() {
    const response = await API.get("/audit/risk-distribution");
    return response.data;
}

export async function getTrustBreakdown() {
    const response = await API.get("/audit/trust-breakdown");
    return response.data;
}

export async function getPropagationAnalytics() {
    const response = await API.get("/audit/propagation-analytics");
    return response.data;
}

export function downloadExcel(exportType) {
    const urls = {
        audit: "/export/audit-excel",
        memory: "/export/memory-excel",
        history: "/export/history-excel",
    };
    const url = `http://localhost:8000${urls[exportType]}`;
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", "");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

export async function clearDatabases() {
    const response = await API.delete("/admin/databases");
    return response.data;
}

/* ===== BENCHMARKS ===== */
export async function getModelBenchmarks() {
    const response = await API.get("/evaluation/model-benchmarks");
    return response.data;
}

export async function queryAgentInvestigator(query) {
    const response = await API.post("/audit/explain-query", null, {
        params: { query },
    });
    return response.data;
}

export async function getMemoryRefreshStats() {
    const response = await API.get("/audit/memory-refresh-stats");
    return response.data;
}

