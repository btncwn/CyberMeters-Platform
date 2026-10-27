import {act,fireEvent,render,screen,waitFor} from '@testing-library/react'
import {MemoryRouter} from 'react-router-dom'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {TlsAuthorizationSettings} from '../../pages/ws/CertificatesPage'
import {api} from '../../api'

vi.mock('../../api',()=>({api:{getTlsAuthorization:vi.fn(),saveTlsAuthorization:vi.fn(),authorizeTlsService:vi.fn(),revokeTlsService:vi.fn()}}))
const permission=(change={})=>({authorization:{enabled:false,generation:0},services:[],verified_domains:[{domain_id:'domain-a',domain:'owned.example.com'}],network_targets:[{id:'target-a',target:'8.8.8.8'}],capabilities:{can_manage:true,assessment_available:true,special_controls_available:true},allowed_services:{https:[443,8443],smtp:[25,587]},consent_version:'tls-special-2026-10-13',...change})
const renderSettings=(workspaceId='workspace-a')=>render(<MemoryRouter><TlsAuthorizationSettings workspaceId={workspaceId} /></MemoryRouter>)
beforeEach(()=>{vi.clearAllMocks();api.getTlsAuthorization.mockResolvedValue(permission());api.saveTlsAuthorization.mockResolvedValue({});api.authorizeTlsService.mockResolvedValue({});api.revokeTlsService.mockResolvedValue({})})

describe('workspace TLS permissions',()=>{
  it('keeps unavailable special probes off the customer permission screen',async()=>{
    api.getTlsAuthorization.mockResolvedValue(permission({capabilities:{can_manage:true,assessment_available:true,special_controls_available:false}}))
    renderSettings()
    await screen.findByText(/Normal scans assess protocols, ciphers and certificates/)
    expect(screen.queryByRole('checkbox',{name:/Allow bounded checks/})).not.toBeInTheDocument()
    expect(screen.getByText(/Additional TLS services/)).toBeInTheDocument()
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
  })
  it('does not offer TLS permissions while the assessment is disabled',async()=>{
    api.getTlsAuthorization.mockResolvedValue(permission({capabilities:{can_manage:true,assessment_available:false}}))
    const view=renderSettings()
    await waitFor(()=>expect(api.getTlsAuthorization).toHaveBeenCalled())
    expect(view.container.querySelector('#tls-permissions')).not.toBeInTheDocument()
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
  })
  it('points special checks to the Active Checks permission page; the old workspace switch is gone',async()=>{
    renderSettings()
    const link=await screen.findByRole('link',{name:'Active Checks permission'})
    expect(link).toHaveAttribute('href','/ws/active-checks/permission')
    expect(screen.queryByRole('checkbox',{name:/Allow bounded checks/})).not.toBeInTheDocument()
    expect(screen.queryByRole('button',{name:'Save TLS permission'})).not.toBeInTheDocument()
    expect(screen.getByText(/Normal scans assess protocols, ciphers and certificates/)).toBeInTheDocument()
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
  })
  it('never reads the legacy enabled flag as a permission (#1011 follow-up)',async()=>{
    api.getTlsAuthorization.mockResolvedValue(permission({authorization:{enabled:true,generation:3}}))
    renderSettings()
    await screen.findByRole('link',{name:'Active Checks permission'})
    expect(screen.queryByText(/Special checks are permitted/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Special checks are not permitted/)).not.toBeInTheDocument()
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
  })
  it('a viewer sees the same link and no service mutations',async()=>{
    api.getTlsAuthorization.mockResolvedValue(permission({capabilities:{can_manage:false,assessment_available:true,special_controls_available:true},services:[{id:'service-a',hostname:'mail.owned.example.com',sni:'mail.owned.example.com',port:587,application_protocol:'smtp'}]}))
    renderSettings()
    expect(await screen.findByRole('link',{name:'Active Checks permission'})).toBeInTheDocument()
    expect(screen.queryByRole('form',{name:'Authorize a TLS service'})).not.toBeInTheDocument()
    expect(screen.queryByRole('button',{name:/Revoke mail\.owned\.example\.com/})).not.toBeInTheDocument()
    expect(api.saveTlsAuthorization).not.toHaveBeenCalled()
  })
  it('lists exactly the services the backend returns as in scope',async()=>{
    // The backend omits a service whose network target was withdrawn; the page invents none.
    api.getTlsAuthorization.mockResolvedValue(permission({services:[{id:'service-live',hostname:'live.owned.example.com',sni:'live.owned.example.com',port:443,application_protocol:'https'}]}))
    renderSettings()
    expect(await screen.findByText(/Additional TLS services \(1\)/)).toBeInTheDocument()
    expect(screen.getByRole('list',{name:'Authorized TLS services'})).toHaveTextContent('live.owned.example.com:443')
  })
  it('requires a verified domain, authorized target and separate service declaration',async()=>{
    renderSettings();await screen.findByRole('link',{name:'Active Checks permission'})
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
    api.getTlsAuthorization.mockImplementation(ws=>ws==='workspace-a'?new Promise(resolve=>{resolveA=resolve}):Promise.resolve(permission({verified_domains:[],network_targets:[]})))
    const view=renderSettings()
    view.rerender(<MemoryRouter><TlsAuthorizationSettings workspaceId="workspace-b" /></MemoryRouter>)
    await screen.findByRole('link',{name:'Active Checks permission'})
    await act(async()=>resolveA(permission({services:[{id:'service-a',hostname:'mail.owned.example.com',sni:'mail.owned.example.com',port:587,application_protocol:'smtp'}]})))
    expect(screen.queryByText(/mail\.owned\.example\.com/)).not.toBeInTheDocument()
    expect(screen.queryByRole('option',{name:'owned.example.com'})).not.toBeInTheDocument()
  })
  it('shows a service save failure without claiming it was recorded',async()=>{
    api.authorizeTlsService.mockRejectedValue(new Error('Permission service unavailable'))
    renderSettings();await screen.findByRole('link',{name:'Active Checks permission'})
    fireEvent.change(screen.getByLabelText('Verified domain'),{target:{value:'domain-a'}})
    fireEvent.change(screen.getByLabelText(/Service hostname/),{target:{value:'mail.owned.example.com'}})
    fireEvent.change(screen.getByLabelText('Authorized IP target'),{target:{value:'target-a'}})
    fireEvent.click(screen.getByRole('checkbox',{name:/I am authorized to test this hostname/}));fireEvent.click(screen.getByRole('button',{name:'Authorize service'}))
    expect(await screen.findByRole('alert')).toHaveTextContent('Permission service unavailable')
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
