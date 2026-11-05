import { useEffect, useState } from 'react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { fetchMikroTikFirewall } from '../api'
import IPCell from './IPCell'
import LogDetail from './LogDetail'

const number = n => new Intl.NumberFormat('en-GB').format(n || 0)
const clock = value => new Date(value).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })

export default function MikroTikDashboard() {
  const [hours, setHours] = useState(24)
  const [family, setFamily] = useState('')
  const [direction, setDirection] = useState('')
  const [result, setResult] = useState('')
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [refresh, setRefresh] = useState(0)
  const [selected, setSelected] = useState(null)
  const [updated, setUpdated] = useState(null)

  useEffect(() => {
    let active = true
    setData(null); setSelected(null); setError('')
    const load = () => fetchMikroTikFirewall({ hours, ip_version: family, direction, result })
      .then(value => { if (active) { setData(value); setUpdated(new Date()); setError('') } })
      .catch(e => { if (active) setError(e.message) })
    load()
    const timer = setInterval(load, 20000)
    return () => { active = false; clearInterval(timer) }
  }, [hours, family, direction, result, refresh])

  const total = data?.total || 0
  const inboundShare = total ? Math.round(data.inbound / total * 100) : 0
  const outboundShare = total ? Math.round(data.outbound / total * 100) : 0
  const metrics = [
    { label: 'WAN events', value: data?.total, icon: '↔', note: 'Logged firewall packets', kind: 'blue' },
    { label: 'Accepted', value: data?.accepted, icon: '✓', note: 'Traffic permitted by your rules', kind: 'green' },
    { label: 'Blocked traffic', value: data?.blocked, icon: '⊘', note: 'Traffic denied by your rules', kind: 'red' },
    { label: 'Outbound events', value: data?.outbound, icon: '↗', note: 'Devices connecting to the Internet', kind: 'blue' },
  ]

  return <div className="network-dashboard">
    <div className="network-heading">
      <div><div className="network-eyebrow">HOME NETWORK / FIREWALL</div><h1>Internet activity</h1><p>Traffic coming from WAN or going to WAN.</p></div>
      <div className="network-toolbar"><span className="network-live"><i /> Live</span><div className="network-segmented" aria-label="Time range">{[[1,'1h'],[6,'6h'],[24,'24h'],[168,'7d']].map(([value,label]) => <button key={value} className={hours===value?'active':''} onClick={()=>setHours(value)}>{label}</button>)}</div><button className="network-icon-button" aria-label="Refresh dashboard" onClick={()=>setRefresh(v=>v+1)}>↻</button></div>
    </div>
    {error && <div role="alert" className="network-error">{data ? 'Refresh failed. Showing the last successful update. ' : 'Could not load firewall activity. '}{error}<button onClick={()=>setRefresh(v=>v+1)}>Retry</button></div>}
    {data && !data.wan_interfaces?.length && <div className="network-error">Select your WAN interface in Settings → Syslog &amp; networks to show Internet activity.</div>}
    <div className="network-filters">
      <span className="network-filter-label">Show</span>
      <label><span className="sr-only">IP version</span><select value={family} onChange={e=>setFamily(e.target.value)}><option value="">IPv4 &amp; IPv6</option><option value="4">IPv4</option><option value="6">IPv6</option></select></label>
      <label><span className="sr-only">Direction</span><select value={direction} onChange={e=>setDirection(e.target.value)}><option value="">All directions</option><option value="inbound">Inbound</option><option value="outbound">Outbound</option></select></label>
      <label><span className="sr-only">Result</span><select value={result} onChange={e=>setResult(e.target.value)}><option value="">All results</option><option value="allow">Accepted</option><option value="block">Blocked Traffic</option></select></label>
      <span className="network-updated">{updated ? `Updated ${updated.toLocaleTimeString('en-GB')}` : 'Loading activity…'}</span>
    </div>
    <div className="network-metrics">{metrics.map(metric => <div key={metric.label} className="network-card network-metric"><div className="network-metric-top"><span>{metric.label}</span><span className={`network-metric-icon ${metric.kind}`}>{metric.icon}</span></div><strong>{data ? number(metric.value) : <span className="network-skeleton">—</span>}</strong><small>{metric.note}</small></div>)}</div>
    <div className="network-chart-grid">
      <section className="network-card"><div className="network-card-heading"><div><h2>Firewall activity</h2><p>Logged packets over time</p></div><div className="network-legend"><span><i className="green" />Accepted</span><span><i className="red" />Blocked Traffic</span></div></div>
        <div className="network-chart">{!data ? <div className="network-chart-loading">Loading chart…</div> : !data.series.length ? <div className="network-empty">No WAN events in this period.</div> : <ResponsiveContainer width="100%" height="100%"><AreaChart data={data.series} margin={{top:12,right:12,left:-22,bottom:0}}><defs><linearGradient id="wanAccepted" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22a06b" stopOpacity={.17}/><stop offset="100%" stopColor="#22a06b" stopOpacity={0}/></linearGradient><linearGradient id="wanBlocked" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ef5261" stopOpacity={.13}/><stop offset="100%" stopColor="#ef5261" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#edf0f4" vertical={false}/><XAxis dataKey="timestamp" tickFormatter={clock} stroke="#94a3b8" tickLine={false} axisLine={false} minTickGap={40} tick={{fontSize:11}}/><YAxis stroke="#94a3b8" tickLine={false} axisLine={false} tick={{fontSize:11}}/><Tooltip labelFormatter={v=>new Date(v).toLocaleString('en-GB')} contentStyle={{background:'#fff',border:'1px solid #e6eaf0',borderRadius:10,fontSize:12}}/><Area type="monotone" dataKey="accepted" name="Accepted" stroke="#22a06b" fill="url(#wanAccepted)" strokeWidth={2}/><Area type="monotone" dataKey="blocked" name="Blocked Traffic" stroke="#ef5261" fill="url(#wanBlocked)" strokeWidth={2}/></AreaChart></ResponsiveContainer>}</div>
      </section>
      <section className="network-card network-direction-card"><div className="network-card-heading"><div><h2>Traffic direction</h2><p>Internet boundary only</p></div><span className="network-subtle-icon">↔</span></div><div className="network-direction-total">{data ? number(total) : '—'}<small>logged packets</small></div><div className="network-direction-bar"><span style={{width:`${inboundShare}%`}}/><span style={{width:`${outboundShare}%`}}/></div>{[['Inbound','WAN → your network',data?.inbound,inboundShare],['Outbound','Your devices → WAN',data?.outbound,outboundShare]].map(([name,note,count,share])=><div className="network-direction-row" key={name}><span className={`network-direction-symbol ${name.toLowerCase()}`}>{name==='Inbound'?'↙':'↗'}</span><div><strong>{name}</strong><small>{note}</small></div><div><strong>{number(count)}</strong><small>{share}%</small></div></div>)}<div className="network-scope-note">Local and inter-VLAN packets are excluded.</div></section>
    </div>
    <div className="network-detail-grid">
      <section className="network-card"><div className="network-card-heading"><div><h2>Firewall categories</h2><p>Your rule groups</p></div><span className="network-small-label">EVENTS</span></div><div className="network-list">{data?.categories.map(item=><div className="network-category-row" key={item.name}><span className="network-category-icon">▦</span><span>{item.name}</span><strong>{number(item.count)}</strong><div className="network-mini-track"><i style={{width:`${Math.max(2,item.count/Math.max(total,1)*100)}%`}}/></div></div>)}{data && !data.categories.length && <div className="network-empty">No matching categories.</div>}{!data && <div className="network-empty">Loading categories…</div>}</div></section>
      <section className="network-card"><div className="network-card-heading"><div><h2>Active devices</h2><p>Outbound Internet events</p></div><span className="network-small-label">EVENTS</span></div><div className="network-list">{data?.devices.map(item=><div className="network-device-row" key={item.ip}><span className="network-device-icon">▣</span><div><strong>{item.name || item.ip}</strong><small>{item.ip}</small></div><div><strong>{number(item.count)}</strong><small>{number(item.blocked)} blocked</small></div></div>)}{data && !data.devices.length && <div className="network-empty">No outbound device activity in this period.</div>}{!data && <div className="network-empty">Loading devices…</div>}</div></section>
    </div>
    <section className="network-card network-events"><div className="network-card-heading"><div><h2>Latest firewall activity</h2><p>Source, destination and the rule that handled each packet</p></div><span className="network-small-label">LATEST 50</span></div><div className="network-table-scroll"><table><thead><tr><th>Time</th><th>Source</th><th>Direction</th><th>Destination</th><th>Result</th><th>Category</th></tr></thead><tbody>{data?.events.map(event=><EventRow key={event.id} event={event} selected={selected===event.id} onSelect={()=>setSelected(v=>v===event.id?null:event.id)}/>)}{data && !data.events.length && <tr><td colSpan={6} className="network-empty">No WAN firewall events match these filters.</td></tr>}{!data && <tr><td colSpan={6} className="network-empty">Loading firewall activity…</td></tr>}</tbody></table></div></section>
    <div className="network-footnote">Counts represent logged packets, not all Internet traffic or unique connections. Port-Scan labels identify your rule groups.</div>
  </div>
}

function EventRow({ event, selected, onSelect }) {
  return <><tr onClick={onSelect} tabIndex={0} onKeyDown={e=>{if(e.key==='Enter')onSelect()}} aria-expanded={selected} className={selected?'selected':''}><td className="network-time">{clock(event.timestamp)}<small>{new Date(event.timestamp).toLocaleDateString('en-GB',{day:'2-digit',month:'short'})}</small></td><td><IPCell ip={event.src_ip} port={event.src_port} deviceName={event.src_device_name} vlan={event.src_device_vlan}/></td><td><span className={`network-direction-pill ${event.direction}`}>{event.direction==='inbound'?'↙':'↗'} {event.direction_label}</span></td><td><IPCell ip={event.dst_ip} port={event.dst_port} deviceName={event.dst_device_name} vlan={event.dst_device_vlan}/></td><td><span className={`network-result ${event.rule_action}`}>{event.rule_action==='allow'?'✓':'⊘'} {event.result_label}</span></td><td><span className="network-rule-category">{event.category_label}</span><small className="network-protocol">{event.protocol?.toUpperCase()}</small></td></tr>{selected && <tr><td colSpan={6}><LogDetail log={event}/></td></tr>}</>
}
