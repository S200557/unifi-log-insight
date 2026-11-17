import { Fragment, useEffect, useState } from 'react'
import { fetchMikroTikDhcpLogs } from '../api'

const eventLabels = { assigned: 'Assigned', deassigned: 'Deassigned' }
const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' })

export default function DhcpLogs() {
  const [range, setRange] = useState('7d')
  const [server, setServer] = useState('')
  const [event, setEvent] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [refresh, setRefresh] = useState(0)
  const [servers, setServers] = useState([])
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [expanded, setExpanded] = useState(null)

  useEffect(() => {
    const request = new AbortController()
    setLoading(true)
    setError(null)
    setExpanded(null)
    fetchMikroTikDhcpLogs({ time_range: range, event, server, search, page }, request.signal)
      .then(result => {
        if (request.signal.aborted) return
        setServers(result.servers)
        setData(result)
      })
      .catch(err => { if (!request.signal.aborted) setError(err.message) })
      .finally(() => { if (!request.signal.aborted) setLoading(false) })
    return () => request.abort()
  }, [range, event, server, search, page, refresh])

  function submitSearch(e) {
    e.preventDefault()
    setPage(1)
    setSearch(searchInput.trim())
  }

  return (
    <section className="network-dashboard" aria-labelledby="dhcp-heading">
      <header className="network-heading">
        <div>
          <h1 id="dhcp-heading">DHCP logs</h1>
          <p>Lease activity received from RouterOS.</p>
        </div>
        <button type="button" className="network-icon-button" title="Refresh DHCP logs" aria-label="Refresh DHCP logs"
          onClick={() => { setPage(1); setRefresh(value => value + 1) }}>↻</button>
      </header>

      <div className="network-filters">
        <select aria-label="Time range" value={range} onChange={e => { setRange(e.target.value); setPage(1) }}>
          <option value="24h">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
          <option value="all">All retained logs</option>
        </select>
        <select aria-label="DHCP event" value={event} onChange={e => { setEvent(e.target.value); setPage(1) }}>
          <option value="">All events</option>
          <option value="assigned">Assigned</option>
          <option value="deassigned">Deassigned</option>
          <option value="other">Other DHCP events</option>
        </select>
        <select aria-label="DHCP server" value={server} onChange={e => { setServer(e.target.value); setPage(1) }}>
          <option value="">All servers</option>
          {servers.map(name => <option key={name} value={name}>{name}</option>)}
        </select>
        <form className="dhcp-search" onSubmit={submitSearch}>
          <input aria-label="Search DHCP logs" placeholder="Device, IP or MAC" value={searchInput} maxLength={255}
            onChange={e => setSearchInput(e.target.value)} />
          <button type="submit">Search</button>
          {search && <button type="button" onClick={() => { setSearchInput(''); setSearch(''); setPage(1) }}>Clear</button>}
        </form>
      </div>

      {error && <div className="network-error" role="alert">Could not load DHCP logs. <button onClick={() => setRefresh(value => value + 1)}>Retry</button></div>}
      <div className="network-card network-events dhcp-table" aria-busy={loading}>
        {loading && <p className="dhcp-status" role="status">Loading DHCP logs…</p>}
        {!loading && !error && data?.events.length === 0 && <p className="dhcp-status" role="status">No DHCP events match these filters.</p>}
        {!loading && !error && data?.events.length > 0 && (
          <div className="network-table-scroll">
            <table aria-label="DHCP lease events">
              <thead><tr>
                <th scope="col">Time</th><th scope="col">Event</th><th scope="col">Device</th>
                <th scope="col">IP address</th><th scope="col">MAC address</th><th scope="col">Server</th>
                <th scope="col">Details</th>
              </tr></thead>
              <tbody>
                {data.events.map(row => (
                  <Fragment key={row.id}>
                    <tr>
                      <td className="network-time"><time dateTime={row.timestamp}>{dateTime.format(new Date(row.timestamp))}</time></td>
                      <td><span className={`network-result${row.event === 'assigned' ? ' allow' : ''}`}>
                        {eventLabels[row.event] || row.event || 'DHCP event'}
                      </span></td>
                      <td>{row.device_name || row.hostname || '—'}
                        {row.device_name && row.hostname && row.device_name !== row.hostname && <small>{row.hostname}</small>}
                      </td>
                      <td className="font-mono">{row.address || '—'}</td>
                      <td className="font-mono whitespace-nowrap">{row.mac?.toUpperCase() || '—'}</td>
                      <td>{row.server || '—'}</td>
                      <td><button type="button" aria-expanded={expanded === row.id} aria-controls={`dhcp-message-${row.id}`}
                        onClick={() => setExpanded(expanded === row.id ? null : row.id)}>
                        {expanded === row.id ? 'Hide message' : 'Show message'}
                      </button></td>
                    </tr>
                    <tr hidden={expanded !== row.id} id={`dhcp-message-${row.id}`}>
                      <td colSpan={7}><pre>{row.raw_log}</pre></td>
                    </tr>
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {(page > 1 || data?.has_more) && (
          <nav className="dhcp-pagination" aria-label="DHCP log pages">
            <button type="button" disabled={loading || page === 1} onClick={() => setPage(value => value - 1)}>Previous</button>
            <span>Page {page}</span>
            <button type="button" disabled={loading || !!error || !data?.has_more || page === 10000}
              onClick={() => setPage(value => value + 1)}>Next</button>
          </nav>
        )}
      </div>
    </section>
  )
}
