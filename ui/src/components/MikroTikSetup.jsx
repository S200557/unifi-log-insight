import React, { useEffect, useState } from 'react'
import { fetchMikroTikConfig, fetchInterfaces, saveMikroTikConfig } from '../api'

const field = 'bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 w-full'
const button = 'px-3 py-2 rounded-lg border border-gray-700 text-sm text-gray-300 hover:bg-gray-800'

export default function MikroTikSetup({ onComplete, onCancel, embedded = false }) {
  const [rows, setRows] = useState([])
  const [rules, setRules] = useState([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  useEffect(() => {
    let active = true
    Promise.all([fetchMikroTikConfig(), fetchInterfaces()]).then(([cfg, observed]) => {
      if (!active) return
      const names = [...new Set([...(cfg.wan_interfaces || []), ...Object.keys(cfg.interface_labels || {}), ...Object.keys(cfg.vpn_networks || {}), ...(cfg.observed_interfaces || []), ...(observed.interfaces || []).map(x => x.name)])]
      setRows(names.length ? names.map(name => ({ name, label: cfg.interface_labels?.[name] || '', role: cfg.wan_interfaces?.includes(name) ? 'wan' : cfg.vpn_networks?.[name] ? 'vpn' : 'lan', cidr: cfg.vpn_networks?.[name]?.cidr || '', badge: cfg.vpn_networks?.[name]?.badge || 'VPN' })) : [{ name: '', label: '', role: 'wan', cidr: '', badge: 'VPN' }])
      setRules(Object.entries(cfg.mikrotik_rule_actions || {}).map(([prefix, action]) => ({ prefix, action })))
      setLoading(false)
    }).catch(e => { if (active) { setError(e.message); setLoading(false) } })
    return () => { active = false }
  }, [])
  const change = (i, key, value) => { setSaved(false); setRows(old => old.map((r, n) => n === i ? { ...r, [key]: value } : r)) }
  async function save(e) {
    e.preventDefault()
    setSaving(true); setError(''); setSaved(false)
    try {
      const named = rows.filter(r => r.name.trim())
      const names = named.map(r => r.name.trim())
      if (new Set(names).size !== names.length) throw new Error('Each interface name must be unique.')
      if (!named.some(r => r.role === 'wan')) throw new Error('Select at least one WAN interface.')
      const prefixes = rules.map(r => r.prefix.trim())
      if (prefixes.some(p => !p) || new Set(prefixes).size !== prefixes.length) throw new Error('Firewall prefixes must be nonempty and unique.')
      await saveMikroTikConfig({
        wan_interfaces: named.filter(r => r.role === 'wan').map(r => r.name.trim()),
        interface_labels: Object.fromEntries(named.map(r => [r.name.trim(), r.label.trim() || r.name.trim()])),
        vpn_networks: Object.fromEntries(named.filter(r => r.role === 'vpn').map(r => [r.name.trim(), { badge: r.badge || 'VPN', cidr: r.cidr.trim() }])),
        mikrotik_rule_actions: Object.fromEntries(rules.map(r => [r.prefix.trim(), r.action])),
      })
      setSaved(true); onComplete?.()
    } catch (e) { setError(e.message) } finally { setSaving(false) }
  }
  const content = <form onSubmit={save} className="max-w-5xl mx-auto space-y-6 p-5 md:p-8">
    <div>
      <p className="text-xs uppercase tracking-widest text-teal-400 mb-2">MikroTik Insights Plus</p>
      <h1 className="text-2xl font-semibold text-gray-100">Syslog & networks</h1>
      <p className="mt-2 text-sm text-gray-400">Receive RouterOS logs and Jotne exporter data. Interfaces below come from received logs or your saved labels. Use the exact RouterOS names; no controller account is needed.</p>
      <div className="mt-4 border border-teal-700/40 bg-teal-500/5 rounded-xl p-4 text-sm text-gray-300">This app observes syslog. Saving these settings changes only this app. It does not connect to your router or change its firewall, logging, users, or scripts.</div>
    </div>
    {loading ? <p className="text-gray-400">Loading observed interfaces…</p> : <>
      <section className="bg-gray-900/50 rounded-xl border border-gray-800 p-4 space-y-3">
        <h2 className="font-semibold text-gray-200">Interfaces & labels</h2>
        <p className="text-sm text-gray-400">Mark your internet-facing interface as WAN, including PPPoE when applicable. VLAN numbers and device trust are never inferred from interface names.</p>
        {rows.map((r,i) => <div key={i} className="grid grid-cols-1 md:grid-cols-12 gap-2 border-b border-gray-800 pb-3">
          <label className="md:col-span-4 text-xs text-gray-400">Interface<input aria-label={`Interface ${i+1}`} className={field} placeholder="Exact RouterOS name" value={r.name} onChange={e => change(i,'name',e.target.value)} maxLength={64}/></label>
          <label className="md:col-span-4 text-xs text-gray-400">Label<input aria-label={`Label ${i+1}`} className={field} value={r.label} onChange={e => change(i,'label',e.target.value)} maxLength={100}/></label>
          <label className="md:col-span-3 text-xs text-gray-400">Role<select aria-label={`Role ${i+1}`} className={field} value={r.role} onChange={e => change(i,'role',e.target.value)}><option value="wan">WAN</option><option value="lan">Local / LAN / VLAN</option><option value="vpn">VPN</option></select></label>
          <button type="button" aria-label={`Remove interface ${i+1}`} className={`${button} md:col-span-1 self-end`} onClick={() => setRows(old => old.filter((_,n) => n!==i))}>×</button>
          {r.role==='vpn' && <><label className="md:col-span-6 text-xs text-gray-400">VPN subnet (optional)<input className={field} placeholder="IPv4 or IPv6 CIDR" value={r.cidr} onChange={e=>change(i,'cidr',e.target.value)}/></label><label className="md:col-span-6 text-xs text-gray-400">Badge<input className={field} value={r.badge} onChange={e=>change(i,'badge',e.target.value)} maxLength={8}/></label></>}
        </div>)}
        <button type="button" className={button} onClick={() => setRows(old=>[...old,{name:'',label:'',role:'lan',cidr:'',badge:'VPN'}])}>+ Add interface</button>
      </section>
      <section className="bg-gray-900/50 rounded-xl border border-gray-800 p-4 space-y-3">
        <h2 className="font-semibold text-gray-200">Firewall prefix meanings</h2>
        <p className="text-sm text-gray-400">Known Jotne prefixes such as FF_D_… and FI_A_… are recognized automatically. Other prefixes remain unknown unless you map their exact meaning here. A logged packet alone does not prove its final firewall verdict.</p>
        {rules.map((r,i)=><div key={i} className="flex gap-2"><input aria-label={`Prefix ${i+1}`} className={field} value={r.prefix} maxLength={100} placeholder="Exact log prefix" onChange={e=>setRules(old=>old.map((x,n)=>n===i?{...x,prefix:e.target.value}:x))}/><select aria-label={`Action ${i+1}`} className={field} value={r.action} onChange={e=>setRules(old=>old.map((x,n)=>n===i?{...x,action:e.target.value}:x))}>{['unknown','allow','block','redirect'].map(a=><option key={a}>{a}</option>)}</select><button type="button" className={button} aria-label={`Remove prefix ${i+1}`} onClick={()=>setRules(old=>old.filter((_,n)=>n!==i))}>×</button></div>)}
        <button type="button" className={button} onClick={()=>setRules(old=>[...old,{prefix:'',action:'unknown'}])}>+ Add prefix mapping</button>
      </section>
      <p className="text-xs text-gray-500">Jotne 5.6 telemetry families, including resources, interface counters, health, pools, routing, PPP, IPsec and neighbors, appear under Router telemetry as they arrive. Optional features can remain empty when the exporter does not emit them.</p>
      {error && <p role="alert" className="text-red-400 text-sm">{error}</p>}
      {saved && <p role="status" className="text-teal-400 text-sm">Settings saved.</p>}
      <div className="flex gap-3"><button disabled={saving} className="px-5 py-2.5 rounded-lg bg-teal-600 hover:bg-teal-500 text-white disabled:opacity-50">{saving?'Saving…':'Save settings'}</button>{onCancel && <button type="button" className={button} onClick={onCancel}>Cancel</button>}</div>
    </>}
    {loading && error && <p role="alert" className="text-red-400">{error}</p>}
  </form>
  return embedded ? content : <div className="h-dvh overflow-y-auto bg-gray-950">{content}</div>
}
