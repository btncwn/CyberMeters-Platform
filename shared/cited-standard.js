// A version may already contain its publication date in parentheses. Keep
// those bytes intact instead of stripping a closing parenthesis and wrapping
// the result again. Web reports and technical PDFs use the same formatter.
export function formatCitedStandard(authority) {
  const name = authority.standard_id || authority.id || authority.authority;
  const version = authority.standard_version || authority.version;
  const versionText = version
    ? (/[()]/.test(String(version)) ? String(version) : `(${version})`)
    : null;
  return [name, versionText].filter(Boolean).join(" ");
}
