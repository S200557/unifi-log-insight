import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import MikroTikDashboard from '../components/MikroTikDashboard'
import { fetchMikroTikFirewall } from '../api'
vi.mock('../api',()=>({fetchMikroTikFirewall:vi.fn()}))
vi.mock('recharts',()=>({ResponsiveContainer:({children})=><div>{children}</div>,AreaChart:()=> <div>Firewall chart</div>,Area:()=>null,XAxis:()=>null,YAxis:()=>null,CartesianGrid:()=>null,Tooltip:()=>null}))
vi.mock('../components/LogDetail',()=>({default:()=> <div>Packet details</div>}))
const response={total:4,accepted:3,blocked:1,inbound:1,outbound:3,series:[],devices:[{ip:'192.0.2.20',name:'My server',count:3,blocked:1}],categories:[{name:'Router-ICMP',count:1}],wan_interfaces:['pppoe-out1'],events:[{id:1,timestamp:'2026-11-05T20:00:00Z',src_ip:'198.51.100.20',dst_ip:'192.0.2.1',dst_device_name:'Router',direction:'inbound',direction_label:'Inbound IPv4',rule_action:'allow',result_label:'Accepted',category_label:'Router-ICMP',protocol:'icmp'}]}
beforeEach(()=>{vi.clearAllMocks();fetchMikroTikFirewall.mockResolvedValue(response)})
describe('WAN firewall overview',()=>{
  it('shows real packet endpoints, DHCP labels and requested category fields',async()=>{
    render(<MikroTikDashboard/> )
    expect(await screen.findByText('My server')).toBeInTheDocument()
    expect(screen.getByText('Router')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.20')).toBeInTheDocument()
    expect(screen.getByText('192.0.2.1')).toBeInTheDocument()
    expect(screen.getByText(/Inbound IPv4/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('198.51.100.20'))
    expect(screen.getByText('Packet details')).toBeInTheDocument()
  })
  it('requests IPv6 and outbound filters from the server, not just the visible table',async()=>{
    render(<MikroTikDashboard/> )
    await screen.findByText('My server')
    fireEvent.change(screen.getByRole('combobox',{name:'IP version'}),{target:{value:'6'}})
    fireEvent.change(screen.getByRole('combobox',{name:'Direction'}),{target:{value:'outbound'}})
    await waitFor(()=>expect(fetchMikroTikFirewall).toHaveBeenLastCalledWith(expect.objectContaining({ip_version:'6',direction:'outbound'})))
  })
})
