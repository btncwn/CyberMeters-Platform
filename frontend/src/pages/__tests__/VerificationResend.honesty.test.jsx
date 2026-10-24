import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import SignupPage from '../SignupPage'
import LoginPage from '../LoginPage'
import EmailVerificationPage from '../EmailVerificationPage'
import { api } from '../../api'

vi.mock('../../api', () => ({ api: { authSignup: vi.fn(), authLogin: vi.fn(), resendVerification: vi.fn() } }))
vi.mock('../../context/AuthContext', () => ({ useAuth: () => ({ login: vi.fn() }) }))

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  api.authSignup.mockResolvedValue({})
  api.authLogin.mockRejectedValue(Object.assign(new Error('Something went wrong. Please try again.'), { status: 403, error: 'email_verification_required', code: 'email_verification_required' }))
  api.resendVerification.mockRejectedValueOnce(new Error('Network unavailable')).mockResolvedValue({})
})

async function expectRetryAndGenericSuccess() {
  const resend = screen.getByRole('button', { name: 'Resend verification email' })
  fireEvent.click(resend)
  expect(await screen.findByRole('alert')).toHaveTextContent('Could not send the link right now. Please try again.')
  expect(screen.queryByText(/link is on its way/)).not.toBeInTheDocument()
  fireEvent.click(resend)
  expect(await screen.findByText('If that address has an unverified account, a new link is on its way.')).toBeInTheDocument()
  expect(api.resendVerification).toHaveBeenCalledTimes(2)
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
}

it('signup keeps resend retryable after network failure', async () => {
  render(<MemoryRouter><SignupPage /></MemoryRouter>)
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Customer' } })
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'person@example.com' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password-long-enough' } })
  fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'password-long-enough' } })
  fireEvent.click(screen.getByRole('button', { name: 'Create account' }))
  expect(await screen.findByRole('heading', { name: 'Check your email' })).toBeInTheDocument()
  await expectRetryAndGenericSuccess()
})

it('login keeps resend retryable after network failure', async () => {
  render(<MemoryRouter><LoginPage /></MemoryRouter>)
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'person@example.com' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'password-long-enough' } })
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
  expect(await screen.findByText('Email not verified')).toBeInTheDocument()
  await expectRetryAndGenericSuccess()
})

it('verification page keeps resend retryable after network failure', async () => {
  render(<MemoryRouter initialEntries={['/verify-email?error=expired']}><EmailVerificationPage /></MemoryRouter>)
  fireEvent.change(screen.getByPlaceholderText('you@example.com'), { target: { value: 'person@example.com' } })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Resend verification email' })).toBeEnabled())
  await expectRetryAndGenericSuccess()
})
