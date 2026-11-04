import React, { useEffect, useState } from 'react'
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { fetchMikroTikStatus, fetchMikroTikResources, fetchMikroTikTelemetry } from '../api'

const time = value => value ? new Date(value).toLocaleString() : '—'
const percent = value => value == null ? '—' : `${Number(value).toFixed(1)}%`
const bps = value => value == null ? '—' : value >= 1e6 ? `${(value/1e6).toFixed(2)} Mbps` : `${(value/1e3).toFixed(1)} Kbps`
const names = {resource:'System resources',sysinfo:'Device information',if_traffic:'Interface counters',health:'Health sensors',pool:'Address pools',route:'Routes',ppp:'PPP sessions',ipsec:'IPsec peers',neighbor:'Neighbors',address_lists:'Address list counts',kids:'Device traffic',wifi:'Wireless clients',upnp:'UPnP mappings',version:'Collector version',ntp:'Time synchronization',interface:'Interface information',ospf:'OSPF neighbors',bgp:'BGP sessions'}

export default function RouterTelemetry() {
  const [status,setStatus]=useState(null), [data,setData]=useState(null), [records,setRecords]=useState([])
  const [host,setHost]=useState(''), [family,setFamily]=useState('pool'), [hours,setHours]=useState(24)
  const [error,setError]=useState(''), [loading,setLoading]=useState(true), [updated,setUpdated]=useState(null)
  useEffect(()=>{
    let active=true
    const refresh=()=>fetchMikroTikStatus().then(s=>{if(active){setStatus(s);setHost(old=>old || s.routers?.[0]?.router_host || '')}}).catch(e=>{if(active)setError(e.message)})
    refresh(); const timer=setInterval(refresh,30000)
    return()=>{active=false;clearInterval(timer)}
  },[])
  useEffect(()=>{
    let active=true
    setLoading(true)
    const refresh=()=>Promise.all([fetchMikroTikResources({host,hours}),fetchMikroTikTelemetry({host,hours,family,limit:300})]).then(([r,t])=>{
      if(active){setData(r);setRecords(t.snapshots||t.data||[]);setError('');setLoading(false);setUpdated(new Date())}
    }).catch(e=>{if(active){setError(e.message);setLoading(false)}})
    refresh();const timer=setInterval(refresh,15000)
    return()=>{active=false;clearInterval(timer)}
  },[host,hours,family])
  const latest=data?.series?.at(-1), info=status?.device_info?.find(x=>x.router_host===host)?.fields
  const seen=new Set(), snapshots=records.filter(r=>{const f=r.fields||{};const key=[r.router_host,f.name||f['.id']||f.pool||f['mac-address']||f['dst-address']||f.nid||f.list||r.id].join('|');if(seen.has(key))return false;seen.add(key);return true})
  const columns=[...new Set(snapshots.slice(0,50).flatMap(r=>Object.keys(r.fields||{})))].filter(k=>k!=='script').slice(0,16)
  return <div className="h-full overflow-auto p-4 md:p-6 space-y-5 text-gray-200">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-xs tracking-widest uppercase text-teal-400">RouterOS · Jotne exporter</p><h1 className="text-2xl font-semibold mt-1">Router telemetry</h1><p className="text-xs text-gray-500 mt-1">Received syslog only · Refreshed {updated?.toLocaleTimeString()||'—'}</p></div><div className="flex gap-2"><select aria-label="Router" className="bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm" value={host} onChange={e=>setHost(e.target.value)}><option value="" disabled>Select observed router</option>{status?.routers?.map(r=><option key={r.router_host} value={r.router_host}>{r.router_host}</option>)}</select><select aria-label="Telemetry time range" className="bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm" value={hours} onChange={e=>setHours(Number(e.target.value))}><option value={1}>Last hour</option><option value={6}>Last 6 hours</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option></select></div></div>
    {error&&<p role="alert" className="border border-red-700 rounded-lg p-3 text-red-400">{error}</p>}
    {info&&<p className="text-sm text-gray-400">{info.identity} · {info.model||info['board-name']} · RouterOS {info.version}</p>}
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">{[['CPU',percent(latest?.cpu)],['Memory used',percent(latest?.memory)],['Disk used',percent(latest?.disk)],['Uptime',latest?.uptime||'—']].map(([label,value])=><div key={label} className="border border-gray-800 bg-gray-900/50 rounded-xl p-4"><p className="text-xs text-gray-400 uppercase tracking-wider">{label}</p><p className="text-2xl font-semibold mt-2 text-gray-100">{value}</p></div>)}</div>
    <section className="border border-gray-800 rounded-xl bg-gray-900/50 p-4"><h2 className="font-semibold mb-3">Resource history</h2>{data?.series?.length ? <div className="h-64"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data.series}><CartesianGrid stroke="#243040" strokeDasharray="3 3"/><XAxis dataKey="timestamp" tickFormatter={s=>new Date(s).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})} minTickGap={60}/><YAxis domain={[0,100]} unit="%"/><Tooltip labelFormatter={time}/><Legend/>{[['cpu','CPU','#14b8a6'],['memory','Memory','#818cf8'],['disk','Disk','#fbbf24']].map(([key,name,color])=><Area key={key} dataKey={key} name={name} stroke={color} fill={color} fillOpacity={0.08} connectNulls={false} isAnimationActive={false}/>)}</AreaChart></ResponsiveContainer></div>:<p className="text-sm text-gray-500 py-10">{loading?'Loading…':'No resource samples in this time range. The Jotne resource collector must be emitting logs.'}</p>}<p className="text-xs text-gray-500 mt-2">Last resource sample: {time(latest?.timestamp)}</p></section>
    <section className="border border-gray-800 rounded-xl bg-gray-900/50 p-4 overflow-auto"><h2 className="font-semibold mb-3">Interfaces</h2><table className="w-full text-sm text-left"><thead className="text-xs uppercase text-gray-500"><tr>{['Interface','Receive rate','Transmit rate','RX drops','TX drops','Sample time'].map(x=><th key={x} className="p-2">{x}</th>)}</tr></thead><tbody>{data?.interfaces?.map(r=><tr key={`${r.router_host}/${r.name}`} className="border-t border-gray-800"><td className="p-2 font-mono">{r.name}</td><td className="p-2 text-teal-400">{bps(r.rx_bps)}</td><td className="p-2 text-indigo-400">{bps(r.tx_bps)}</td><td className="p-2">{r.rx_drops||'—'}</td><td className="p-2">{r.tx_drops||'—'}</td><td className="p-2 text-gray-500">{time(r.timestamp)}</td></tr>)}</tbody></table>{!data?.interfaces?.length&&<p className="text-sm text-gray-500 py-5">No interface counter samples received.</p>}<p className="text-xs text-gray-500 mt-3">Rates use successive counter samples. Resets, duplicate timestamps and gaps over 15 minutes show “—”. Firewall flow views count logged events; these interface rates measure exported counters.</p></section>
    {!!data?.health?.length&&<section className="flex flex-wrap gap-3">{data.health.map((r,i)=><div key={i} className="border border-gray-800 rounded-lg p-3 text-sm"><span className="text-gray-400">{r.fields.name||'Health'} </span>{r.fields.value} {r.fields.type}</div>)}</section>}
    <section className="border border-gray-800 rounded-xl bg-gray-900/50 p-4"><div className="flex items-center justify-between gap-3 mb-4"><h2 className="font-semibold">Exporter records</h2><select aria-label="Exporter family" className="bg-gray-900 border border-gray-700 rounded-lg p-2 text-sm" value={family} onChange={e=>setFamily(e.target.value)}>{[...new Set(['pool',...(status?.families||[]).map(x=>x.family)])].filter(Boolean).map(f=><option key={f} value={f}>{names[f]||f}</option>)}</select></div><div className="overflow-auto"><table className="w-full text-xs text-left"><thead className="text-gray-500"><tr><th className="p-2">Sample time</th>{columns.map(c=><th key={c} className="p-2 whitespace-nowrap">{c}</th>)}</tr></thead><tbody>{snapshots.map(r=><tr key={r.id} className="border-t border-gray-800"><td className="p-2 whitespace-nowrap text-gray-500">{time(r.timestamp)}</td>{columns.map(c=><td key={c} className="p-2 max-w-sm break-words">{String(r.fields?.[c]??'—')}</td>)}</tr>)}</tbody></table></div>{!snapshots.length&&<p className="text-sm text-gray-500 py-8">No {names[family]||family} records received in this time range.</p>}<p className="text-xs text-gray-500 mt-3">Latest samples per observed record, within the most recent 300 events. All fields and history remain available in Log Stream → telemetry.</p></section>
    {data?.truncated&&<p className="text-amber-400 text-sm">The chart sample limit was reached. Choose a shorter time range.</p>}
  </div>
}
