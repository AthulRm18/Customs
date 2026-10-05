import { useState } from 'react';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import Dashboard from './pages/Dashboard';
import AgentActivity from './pages/AgentActivity';
import MCPServers from './pages/MCPServers';
import Policies from './pages/Policies';
import Threats from './pages/Threats';
import AuditLog from './pages/AuditLog';
import Simulator from './pages/Simulator';

const PAGES = {
  dashboard: Dashboard,
  activity:  AgentActivity,
  servers:   MCPServers,
  policies:  Policies,
  threats:   Threats,
  audit:     AuditLog,
  simulator: Simulator,
};

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [customsEnabled, setCustomsEnabled] = useState(true);

  const Page = PAGES[activePage] || Dashboard;

  return (
    <div className="shell">
      <Sidebar
        activePage={activePage}
        setActivePage={setActivePage}
      />
      <div className="main">
        <Topbar
          activePage={activePage}
          customsEnabled={customsEnabled}
          setCustomsEnabled={setCustomsEnabled}
        />
        <div className="page">
          <Page
            customsEnabled={customsEnabled}
            setCustomsEnabled={setCustomsEnabled}
            setActivePage={setActivePage}
          />
        </div>
      </div>
    </div>
  );
}
