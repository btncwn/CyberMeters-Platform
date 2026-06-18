import { Settings } from 'lucide-react'

export default function SettingsPage() {
  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-sm text-gray-400 mt-0.5">Platform configuration and preferences</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Account */}
        <div className="card p-6 space-y-4">
          <h2 className="text-sm font-bold text-gray-900">Account</h2>
          <div className="space-y-3">
            <div>
              <label className="label mb-1 block">Name</label>
              <input className="input" defaultValue="Turhan" readOnly />
            </div>
            <div>
              <label className="label mb-1 block">Email</label>
              <input className="input" defaultValue="ttrnn47@gmail.com" readOnly />
            </div>
          </div>
        </div>

        {/* API */}
        <div className="card p-6 space-y-4">
          <h2 className="text-sm font-bold text-gray-900">API</h2>
          <div>
            <label className="label mb-1 block">Base URL</label>
            <input
              className="input mono text-xs"
              defaultValue={import.meta.env.VITE_API_BASE_URL || 'https://cybermeters-platform.ttrnn47.workers.dev/api'}
              readOnly
            />
          </div>
          <p className="text-xs text-gray-400">Set <code className="mono bg-gray-100 px-1 py-0.5 rounded">VITE_API_BASE_URL</code> in your <code className="mono bg-gray-100 px-1 py-0.5 rounded">.env</code> file to change the API endpoint.</p>
        </div>

        {/* Notifications */}
        <div className="card p-6">
          <h2 className="text-sm font-bold text-gray-900 mb-4">Notifications</h2>
          <p className="text-xs text-gray-400">Alert configuration coming soon.</p>
        </div>
      </div>
    </div>
  )
}
