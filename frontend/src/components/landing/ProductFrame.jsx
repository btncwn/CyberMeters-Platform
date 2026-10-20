// One frame for every product screen on the public site, so each screen reads
// as the same product: a quiet window bar with the app address, then the
// screen itself. `label` names the screen for assistive technology.
export default function ProductFrame({ label, path, children, caption, className = '' }) {
  return (
    <figure
      aria-label={label}
      className={`rounded-[16px] bg-white border border-[#DDE2EE] shadow-[0_30px_60px_-40px_rgba(18,26,46,.5)] overflow-hidden ${className}`}
    >
      <div className="flex items-center gap-3 px-5 h-11 border-b border-[#E6EAF3] bg-[#F7F8FC]">
        <span className="flex gap-1.5" aria-hidden="true">
          <span className="w-2.5 h-2.5 rounded-full bg-[#D5DBEA]" />
          <span className="w-2.5 h-2.5 rounded-full bg-[#D5DBEA]" />
          <span className="w-2.5 h-2.5 rounded-full bg-[#D5DBEA]" />
        </span>
        <span className="min-w-0 truncate text-[14px] text-[#626B80]">app.cybermeters.com{path}</span>
      </div>
      {children}
      {caption && (
        <figcaption className="px-6 py-4 bg-[#F7F8FC] border-t border-[#E6EAF3] text-[14px] leading-[1.55] text-[#5A6378]">
          {caption}
        </figcaption>
      )}
    </figure>
  )
}
