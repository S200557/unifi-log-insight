const icons = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></>,
  logs: <><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></>,
  'flow-view': <><path d="M3 7h13l-4-4M21 17H8l4 4M3 7l4 4M21 17l-4-4"/></>,
  'threat-map': <><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z"/></>,
  router: <><rect x="3" y="9" width="18" height="11" rx="2"/><path d="M7 9V3M17 9V3M7 15h.01M11 15h.01M15 15h2"/></>,
}
const names = { dashboard:'Overview', logs:'Firewall logs', 'flow-view':'Traffic flows', 'threat-map':'World map', router:'Gateway' }

export default function NetworkSidebar({ activeTab, onNavigate, onSettings }) {
  return <aside className="network-sidebar"><div className="network-site"><span className="network-site-icon">⌂</span><div><strong>Home network</strong><small>MikroTik RB5009</small></div><i /></div><div className="network-nav-heading">NETWORK</div><nav aria-label="Network navigation">{Object.entries(names).map(([id,label])=><button key={id} title={label} className={activeTab===id?'active':''} onClick={()=>onNavigate(id)} aria-current={activeTab===id?'page':undefined}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">{icons[id]}</svg><span>{label}</span></button>)}</nav><div className="network-sidebar-bottom"><button onClick={onSettings}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6"><path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="8" cy="18" r="2"/></svg><span>Settings</span></button><div className="network-sidebar-note">Firewall insights<br/><span>IPv4 &amp; IPv6 · WAN only</span></div></div></aside>
}
