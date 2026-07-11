import { useEffect } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import Layout from "./components/Layout";
import ChatPage from "./pages/ChatPage";
import DashboardPage from "./pages/DashboardPage";
import MemoryVaultPage from "./pages/MemoryVaultPage";
import HITLPage from "./pages/HITLPage";
import ThreatAnalysisPage from "./pages/ThreatAnalysisPage";
import ModelPerformancePage from "./pages/ModelPerformancePage";
import AgentInvestigatorPage from "./pages/AgentInvestigatorPage";
import "./App.css";

function App() {
    const location = useLocation();

    useEffect(() => {
        const path = location.pathname;
        let title = "AttackLayer";

        switch (path) {
            case "/chat":
                title = "Chat - AttackLayer";
                break;
            case "/dashboard":
                title = "SOC Dashboard - AttackLayer";
                break;
            case "/memory-vault":
                title = "Memory Vault - AttackLayer";
                break;
            case "/hitl":
                title = "Human Review Center - AttackLayer";
                break;
            case "/threat-analysis":
                title = "Threat Analysis & Intelligence - AttackLayer";
                break;
            case "/model-performance":
                title = "Model Performance - AttackLayer";
                break;
            case "/agent-investigator":
                title = "Agent Investigator - AttackLayer";
                break;
            default:
                title = "AttackLayer";
        }

        document.title = title;
    }, [location]);

    return (
        <Routes>
            <Route path="/" element={<Navigate to="/chat" replace />} />
            <Route
                path="/chat"
                element={
                    <div className="app-shell">
                        <ChatPage />
                    </div>
                }
            />
            <Route
                path="/dashboard"
                element={
                    <Layout>
                        <DashboardPage />
                    </Layout>
                }
            />
            <Route
                path="/memory-vault"
                element={
                    <Layout>
                        <MemoryVaultPage />
                    </Layout>
                }
            />
            <Route
                path="/hitl"
                element={
                    <Layout>
                        <HITLPage />
                    </Layout>
                }
            />
            <Route
                path="/threat-analysis"
                element={
                    <Layout>
                        <ThreatAnalysisPage />
                    </Layout>
                }
            />
            <Route
                path="/model-performance"
                element={
                    <Layout>
                        <ModelPerformancePage />
                    </Layout>
                }
            />
            <Route
                path="/agent-investigator"
                element={
                    <Layout>
                        <AgentInvestigatorPage />
                    </Layout>
                }
            />
        </Routes>
    );
}

export default App;
