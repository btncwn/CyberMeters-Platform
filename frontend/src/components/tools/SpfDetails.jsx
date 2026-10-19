import { StateBadge } from './ToolResult'

// Presentation of the SPF result: records, the lookup budget and the include
// tree the resolver walked. All wording comes from the API result.
function nodeState(node) {
  if (node.stopped) return node.status === 'temperror' ? 'unknown' : 'fail'
  return 'pass'
}

function TreeNode({ node }) {
  return (
    <li className="space-y-2">
      <div className="flex flex-wrap gap-2 items-start text-sm">
        <StateBadge state={nodeState(node)} />
        <span className="font-mono break-all">{node.via === 'root' ? node.domain : `${node.via}:${node.domain}`}</span>
        <span className="text-gray-500">{node.lookups} lookup{node.lookups === 1 ? '' : 's'}</span>
      </div>
      {node.record && node.via !== 'root' && <p className="font-mono text-xs text-gray-500 break-all pl-1">{node.record}</p>}
      {node.stopped_reason && <p className="text-sm text-gray-700">{node.stopped_reason}</p>}
      {node.children?.length > 0 && (
        <ul className="border-l-2 border-gray-200 pl-4 space-y-3">{node.children.map((child, i) => <TreeNode key={`${child.domain}-${i}`} node={child} />)}</ul>
      )}
    </li>
  )
}

function Meter({ label, used, limit }) {
  if (used == null) return null
  const over = used > limit
  const pct = Math.min(100, Math.round((used / limit) * 100))
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-sm"><span className="font-semibold">{label}</span><span>{over ? `over ${limit}` : `${used} of ${limit}`}</span></div>
      <div className="h-2 rounded-full bg-gray-200" role="img" aria-label={`${label}: ${used} of ${limit}`}>
        <div className={`h-2 rounded-full ${over || used === limit ? 'bg-red-500' : used >= limit * 0.8 ? 'bg-amber-500' : 'bg-emerald-500'}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

export default function SpfDetails({ result }) {
  const { records = [], tree, lookups, void_lookups: voids, all } = result
  return (
    <div className="space-y-8">
      <section aria-labelledby="spf-record-heading" className="space-y-3">
        <h2 id="spf-record-heading" className="text-lg font-bold">{records.length > 1 ? 'The records' : 'The record'}</h2>
        {records.length > 0
          ? records.map((value) => <pre key={value} className="rounded-xl bg-gray-900 text-gray-100 p-4 text-sm whitespace-pre-wrap break-all">{value}</pre>)
          : <p className="text-sm text-gray-700">No SPF record was observed.</p>}
        {all && <p className="text-sm text-gray-700"><span className="font-semibold">{all.label}.</span> {all.detail}</p>}
      </section>

      {records.length > 0 && lookups && (
        <section aria-labelledby="budget-heading" className="space-y-4">
          <h2 id="budget-heading" className="text-lg font-bold">DNS lookup budget</h2>
          <Meter label="DNS lookups" used={lookups.stopped_at_limit ? lookups.limit + 1 : lookups.used} limit={lookups.limit} />
          <Meter label="Lookups with no answer" used={voids?.used} limit={voids?.limit} />
          <p className="text-sm text-gray-600">Receivers stop evaluating SPF at 10 DNS lookups (include, a, mx, ptr, exists, redirect) or at 2 lookups that return nothing, and SPF then fails for every message.</p>
        </section>
      )}

      {tree && (
        <section aria-labelledby="tree-heading" className="space-y-3">
          <h2 id="tree-heading" className="text-lg font-bold">Include tree</h2>
          <p className="text-sm text-gray-600">Every record the check followed, with the lookups each one costs including everything below it.</p>
          <ul className="space-y-3"><TreeNode node={tree} /></ul>
        </section>
      )}
    </div>
  )
}
