import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import MikroTikSetup from '../components/MikroTikSetup'
import { fetchMikroTikConfig, fetchInterfaces, saveMikroTikConfig } from '../api'

vi.mock('../api',()=>({fetchMikroTikConfig:vi.fn(),fetchInterfaces:vi.fn(),saveMikroTikConfig:vi.fn()}))
beforeEach(()=>{
  vi.clearAllMocks()
  fetchMikroTikConfig.mockResolvedValue({wan_interfaces:['pppoe-out1'],interface_labels:{'pppoe-out1':'Internet',bridge:'LAN'},observed_interfaces:['MGMT-50'],vpn_networks:{},mikrotik_rule_actions:{}})
  fetchInterfaces.mockResolvedValue({interfaces:[]})
  saveMikroTikConfig.mockResolvedValue({success:true})
})
describe('passive RouterOS setup',()=>{
  it('saves actual interface names and local settings without a controller form',async()=>{
    const done=vi.fn()
    render(<MikroTikSetup onComplete={done}/> )
    await screen.findByDisplayValue('pppoe-out1')
    expect(screen.getByDisplayValue('MGMT-50')).toBeInTheDocument()
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button',{name:'Save settings'}))
    await waitFor(()=>expect(done).toHaveBeenCalled())
    expect(saveMikroTikConfig).toHaveBeenCalledWith(expect.objectContaining({wan_interfaces:['pppoe-out1'],interface_labels:expect.objectContaining({'MGMT-50':'MGMT-50'})}))
  })
  it('rejects duplicate interface names before saving',async()=>{
    render(<MikroTikSetup/> )
    await screen.findByDisplayValue('pppoe-out1')
    fireEvent.change(screen.getByLabelText('Interface 2'),{target:{value:'pppoe-out1'}})
    fireEvent.click(screen.getByRole('button',{name:'Save settings'}))
    expect(await screen.findByRole('alert')).toHaveTextContent('unique')
    expect(saveMikroTikConfig).not.toHaveBeenCalled()
  })
})
