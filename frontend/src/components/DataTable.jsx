/**
 * DataTable — reusable table component.
 *
 * Props:
 *   columns   Array of { key, label, render? }
 *             render(value, row) → ReactNode  (optional)
 *   rows      Array of data objects
 *   empty     ReactNode shown when rows is empty
 *   className Extra class on the wrapper div
 */
export default function DataTable({ columns = [], rows = [], empty, className = '' }) {
  if (rows.length === 0) {
    return empty ?? (
      <div className="py-12 text-center text-sm text-gray-400">No data yet.</div>
    )
  }

  return (
    <div className={`overflow-x-auto ${className}`}>
      <table className="data-table w-full">
        <thead>
          <tr>
            {columns.map(col => (
              <th key={col.key}>{col.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.id ?? i}>
              {columns.map(col => (
                <td key={col.key}>
                  {col.render ? col.render(row[col.key], row) : (row[col.key] ?? '—')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
