import React from 'react'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { beforeEach, afterEach, expect, it, vi } from 'vitest'
import FlowView from '../components/FlowView'
import ThreatMap from '../components/ThreatMap'
import { fetchThreatGeo } from '../api'

vi.mock('../platform', () => ({ MIKROTIK: true }))
vi.mock('../api', () => ({ fetchSavedViews: vi.fn().mockResolvedValue({ views: [] }),
  createSavedView: vi.fn(), deleteSavedView: vi.fn(), fetchThreatGeo: vi.fn() }))
vi.mock('../components/SankeyChart', () => ({ default: ({ dims }) => <div>{dims.join(' → ')}</div> }))
vi.mock('../components/ZoneMatrix', () => ({ default: () => <div>Zone matrix data</div> }))
vi.mock('../components/TopIPPairs', () => ({ default: () => <div>IP pairs</div> }))
vi.mock('../components/HostSlidePanel', () => ({ default: () => null }))
vi.mock('../components/ThreatSidebar', () => ({ default: () => null }))
vi.mock('../components/DateRangePicker', () => ({ default: () => null }))
vi.mock('maplibre-gl', () => ({ default: {
  setWorkerUrl: vi.fn(),
  Map: class {
    on() {} once() {} addControl() {} remove() {} triggerRepaint() {}
    getLayer() {} getSource() {} isStyleLoaded() { return true }
  },
  Popup: class {}, NavigationControl: class {}, AttributionControl: class {},
} }))

beforeEach(() => {
  vi.clearAllMocks()
  sessionStorage.clear()
  fetchThreatGeo.mockResolvedValue({ features: [], summary: { total_points: 0, total_events: 0 } })
})
afterEach(cleanup)

it('opens the Zone Matrix and gives the graph meaningful zone/protocol dimensions', async () => {
  render(<FlowView />)
  expect(await screen.findByText('Zone matrix data')).toBeInTheDocument()
  expect(screen.queryByText('UNKNOWN')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Flow Graph' }))
  expect(await screen.findByText('interface_in → protocol → interface_out')).toBeInTheDocument()
})

it('requests WAN activity by default and retains an explicit threat-only mode', async () => {
  render(<ThreatMap />)
  await waitFor(() => expect(fetchThreatGeo).toHaveBeenCalledWith(expect.objectContaining({ mode: 'activity' })))
  fireEvent.click(screen.getByRole('button', { name: 'Threats' }))
  await waitFor(() => expect(fetchThreatGeo).toHaveBeenLastCalledWith(expect.objectContaining({ mode: 'threats' })))
})

it('reports failed map requests instead of silently displaying an empty map', async () => {
  fetchThreatGeo.mockRejectedValue(new Error('Service unavailable'))
  render(<ThreatMap />)
  expect(await screen.findByText('Map data could not be loaded')).toBeInTheDocument()
  expect(screen.getByText('Service unavailable')).toBeInTheDocument()
})
