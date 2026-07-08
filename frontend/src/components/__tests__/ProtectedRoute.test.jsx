import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import ProtectedRoute from '../ProtectedRoute'
import { useAuth } from '../../context/AuthContext'

vi.mock('../../context/AuthContext', () => ({
  useAuth: vi.fn(),
}))

function renderGuard() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route path="/login" element={<p>login page</p>} />
        <Route
          path="/dashboard"
          element={(
            <ProtectedRoute>
              <p>secret dashboard</p>
            </ProtectedRoute>
          )}
        />
      </Routes>
    </MemoryRouter>,
  )
}

describe('ProtectedRoute (auth guard)', () => {
  it('holds on a spinner while the session is validating — no premature redirect', () => {
    useAuth.mockReturnValue({ isAuthenticated: false, isLoading: true })
    renderGuard()
    expect(screen.queryByText('secret dashboard')).not.toBeInTheDocument()
    expect(screen.queryByText('login page')).not.toBeInTheDocument()
  })

  it('redirects unauthenticated visitors to /login', () => {
    useAuth.mockReturnValue({ isAuthenticated: false, isLoading: false })
    renderGuard()
    expect(screen.getByText('login page')).toBeInTheDocument()
    expect(screen.queryByText('secret dashboard')).not.toBeInTheDocument()
  })

  it('renders the protected content for an authenticated session', () => {
    useAuth.mockReturnValue({ isAuthenticated: true, isLoading: false })
    renderGuard()
    expect(screen.getByText('secret dashboard')).toBeInTheDocument()
  })
})
