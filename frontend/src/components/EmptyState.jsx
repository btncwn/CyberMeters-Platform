import { ShieldOff } from 'lucide-react'

export default function EmptyState({ icon: Icon = ShieldOff, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center px-6">
      <div className="w-14 h-14 rounded-2xl bg-brand-50 border border-brand-100 flex items-center justify-center mb-4">
        <Icon className="w-6 h-6 text-brand-600" />
      </div>
      <h3 className="text-gray-900 font-bold text-base mb-1">{title}</h3>
      {description && <p className="text-gray-400 text-sm mb-5 max-w-xs leading-relaxed">{description}</p>}
      {action}
    </div>
  )
}
