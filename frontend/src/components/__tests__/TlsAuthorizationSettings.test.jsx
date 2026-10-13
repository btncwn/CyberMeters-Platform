import {act,fireEvent,render,screen,waitFor} from '@testing-library/react'
import {MemoryRouter} from 'react-router-dom'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {TlsAuthorizationSettings} from '../../pages/ws/CertificatesPage'
import {api} from '../../api'

vi.mock('../../api',()=>({api:{getTlsAuthorization:vi.fn(),saveTlsAuthorization:vi.fn(),authorizeTlsService:vi.fn(),revokeTlsService:vi.fn()}}))
const permission=(change={})=>({authorization:{enabled:false,generation:0},services:[],verified_domains:[{domain_id:'domain-a',domain:'owned.example.com'}],network_targets:[{id:'target-a',target:'8.8.8.8'}],capabilities:{can_manage:true,assessment_available:true},allowed_services:{https:[443,8443],smtp:[25,587]},consent_version:'tls-special-2026-10-13',...change})
const renderSettings=(workspaceId='workspace-a')=>render(<MemoryRouter><TlsAuthorizationSettings workspaceId={workspaceId} /></MemoryRouter>)
beforeEach(()=>{vi.clearAllMocks();api.getTlsAuthorization.mockResolvedValue(permission());api.saveTlsAuthorization.mockResolvedValue({});api.authorizeTlsService.mockResolvedValue({});api.revokeTlsService.mockResolvedValue({})})

describe('workspace TLS permissions',()=>{
  it('does not offer TLS permissions while the assessment is disabled',async()=>{
    api.getTlsAuthorization.mockResolvedValue(permission({capabilities:{can_manage:true,assessment_available:false}}))
    const view=renderSettings()
    await waitFor(()=>expect(api.getTlsAuthorization).toHaveBeenCalled())
    expect(view.container.querySelector('#tls-permissions')).not.toBeInTheDocument()
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
  })
  it('keeps normal scans independent and asks for one explicit versioned permission for special probes',async()=>{
    renderSettings()
    const toggle=await screen.findByRole('checkbox',{name:/Allow bounded checks/})
    expect(toggle).not.toBeChecked()
    expect(screen.getByText(/Normal scans assess protocols, ciphers and certificates/)).toBeInTheDocument()
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
    fireEvent.click(toggle);fireEvent.click(screen.getByRole('button',{name:'Save TLS permission'}))
    await waitFor(()=>expect(api.saveTlsAuthorization).toHaveBeenCalledWith('workspace-a',{enabled:true,authorization_confirmed:true,consent_version:'tls-special-2026-10-13'}))
    expect(await screen.findByRole('status')).toHaveTextContent('No scan was started')
  })
  it('revokes permission without a new attestation',async()=>{
    api.getTlsAuthorization.mockResolvedValue(permission({authorization:{enabled:true,generation:3}}))
    renderSettings();fireEvent.click(await screen.findByRole('checkbox',{name:/Allow bounded checks/}));fireEvent.click(screen.getByRole('button',{name:'Save TLS permission'}))
    await waitFor(()=>expect(api.saveTlsAuthorization).toHaveBeenCalledWith('workspace-a',{enabled:false}))
    expect(await screen.findByRole('status')).toHaveTextContent('Running special checks must stop')
  })
  it('makes the permission read-only for viewers and does not expose service mutations',async()=>{
    api.getTlsAuthorization.mockResolvedValue(permission({capabilities:{can_manage:false,assessment_available:true}}))
    renderSettings();expect(await screen.findByRole('checkbox',{name:/Allow bounded checks/})).toBeDisabled()
    expect(screen.queryByRole('button',{name:'Save TLS permission'})).not.toBeInTheDocument()
    expect(screen.queryByRole('form',{name:'Authorize a TLS service'})).not.toBeInTheDocument()
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
  })
  it('requires a verified domain, authorized target and separate service declaration',async()=>{
    renderSettings();await screen.findByRole('checkbox',{name:/Allow bounded checks/})
    const submit=screen.getByRole('button',{name:'Authorize service'});expect(submit).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Verified domain'),{target:{value:'domain-a'}})
    fireEvent.change(screen.getByLabelText(/Service hostname/),{target:{value:'mail.owned.example.com'}})
    fireEvent.change(screen.getByLabelText('Service and port'),{target:{value:'smtp:587'}})
    fireEvent.change(screen.getByLabelText('Authorized IP target'),{target:{value:'target-a'}})
    expect(submit).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox',{name:/I am authorized to test this hostname/}));fireEvent.click(submit)
    await waitFor(()=>expect(api.authorizeTlsService).toHaveBeenCalledWith('workspace-a',{domain_id:'domain-a',hostname:'mail.owned.example.com',sni:'mail.owned.example.com',port:587,application_protocol:'smtp',network_target_id:'target-a',authorization_confirmed:true}))
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
  })
  it('revokes only the selected service',async()=>{
    api.getTlsAuthorization.mockResolvedValue(permission({services:[{id:'service-a',hostname:'mail.owned.example.com',sni:'mail.owned.example.com',port:587,application_protocol:'smtp'}]}))
    renderSettings();fireEvent.click(await screen.findByRole('button',{name:'Revoke mail.owned.example.com:587'}))
    await waitFor(()=>expect(api.revokeTlsService).toHaveBeenCalledWith('workspace-a','service-a'))
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
  })
  it('discards a prior workspace response and never shows its permissions in the next workspace',async()=>{
    let resolveA
    api.getTlsAuthorization.mockImplementation(ws=>ws==='workspace-a'?new Promise(resolve=>{resolveA=resolve}):Promise.resolve(permission({authorization:{enabled:false,generation:0},verified_domains:[],network_targets:[]})))
    const view=renderSettings()
    view.rerender(<MemoryRouter><TlsAuthorizationSettings workspaceId="workspace-b" /></MemoryRouter>)
    await screen.findByRole('checkbox',{name:/Allow bounded checks/})
    await act(async()=>resolveA(permission({authorization:{enabled:true,generation:7}})))
    expect(screen.getByRole('checkbox',{name:/Allow bounded checks/})).not.toBeChecked()
    expect(screen.queryByRole('option',{name:'owned.example.com'})).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox',{name:/Allow bounded checks/}));fireEvent.click(screen.getByRole('button',{name:'Save TLS permission'}))
    await waitFor(()=>expect(api.saveTlsAuthorization).toHaveBeenCalledWith('workspace-b',expect.any(Object)))
  })
  it('shows save failure without claiming permission was recorded',async()=>{
    api.saveTlsAuthorization.mockRejectedValue(new Error('Permission service unavailable'))
    renderSettings();fireEvent.click(await screen.findByRole('checkbox',{name:/Allow bounded checks/}));fireEvent.click(screen.getByRole('button',{name:'Save TLS permission'}))
    expect(await screen.findByRole('alert')).toHaveTextContent('Permission service unavailable')
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
