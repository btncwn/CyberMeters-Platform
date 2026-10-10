import { useEffect, useState } from 'react'
import { api } from '../api'

// One-click verification offer for a domain whose verification token exists.
// `tokenKey` changes whenever a new token is issued, so the offer is re-fetched
// against the current token. Any failure resolves to null: the manual DNS
// instructions are always shown, so a missing offer is never an error state.
export function useDomainConnectOffer(domainId, workspaceId, tokenKey) {
  const [offer, setOffer] = useState(null)
  useEffect(() => {
    setOffer(null)
    if (!domainId || !tokenKey) return undefined
    let cancelled = false
    let pending
    try { pending = api.getDomainConnectOffer(domainId, workspaceId) } catch { return undefined }
    Promise.resolve(pending)
      .then((res) => { if (!cancelled && res?.available && res.apply_url) setOffer(res) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [domainId, workspaceId, tokenKey])
  return offer
}
