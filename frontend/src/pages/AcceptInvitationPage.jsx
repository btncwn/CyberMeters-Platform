import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { CheckCircle, AlertTriangle, RefreshCw } from 'lucide-react'
import { api } from '../api'

export default function AcceptInvitationPage() {
  const { token } = useParams()
  const navigate = useNavigate()
  const [status, setStatus] = useState('loading')
  const [message, setMessage] = useState('Accepting invitation...')

  useEffect(() => {
    async function accept() {
      try {
        await api.acceptWorkspaceInvitation(token)
        setStatus('success')
        setMessage('Invitation accepted.')
      } catch (e) {
        setStatus('error')
        setMessage(e.message)
      }
    }
    accept()
  }, [token])

  return (
    <div className="max-w-xl mx-auto px-6 py-16">
      <div className="card p-8 text-center">
        {status === 'loading' ? (
          <RefreshCw className="w-8 h-8 text-brand-500 animate-spin mx-auto mb-4" />
        ) : status === 'success' ? (
          <CheckCircle className="w-8 h-8 text-green-500 mx-auto mb-4" />
        ) : (
          <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-4" />
        )}
        <h1 className="text-xl font-semibold text-gray-900 mb-2">Workspace Invitation</h1>
        <p className="text-sm text-gray-500 mb-6">{message}</p>
        <button
          type="button"
          onClick={() => navigate('/workspaces')}
          className="btn-primary"
        >
          Go to workspaces
        </button>
      </div>
    </div>
  )
}
