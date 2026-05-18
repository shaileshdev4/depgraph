export default function StatsBar({ stats, running }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 text-xs border-t border-border pt-3">
      <Stat label="In graph" value={stats.packagesInGraph ?? "—"} />
      <Stat label="Scanned" value={stats.scanned ?? "—"} />
      <Stat
        label="Vulnerable"
        value={stats.vulnerable ?? 0}
        className={stats.vulnerable > 0 ? "text-red-400" : ""}
      />
      <Stat
        label="Critical"
        value={stats.critical ?? 0}
        className={
          stats.critical > 0 ? "text-red-500 animate-pulse font-bold" : ""
        }
      />
      <Stat label="Spawn" value={stats.spawnMode ?? "—"} />
      <Stat label="Route LLM" value={stats.routeLlm ?? 0} />
      <Stat label="Route fallback" value={stats.routeFallback ?? 0} />
      {stats.truncated && (
        <div className="col-span-full text-gray-500">
          Risk filter: {stats.packagesInGraph} from {stats.originalCount}
        </div>
      )}
      {running && (
        <div className="col-span-full text-cyan-400 animate-pulse">
          Investigating…
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, className = "" }) {
  return (
    <div className="rounded bg-card border border-border px-2 py-1.5">
      <div className="text-gray-500">{label}</div>
      <div className={`font-semibold text-white ${className}`}>{value}</div>
    </div>
  );
}
