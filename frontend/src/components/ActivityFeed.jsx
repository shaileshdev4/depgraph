import { useEffect, useRef } from "react";
import { formatLogLine, logColor } from "../utils/eventProcessor";

export default function ActivityFeed({ logEntries }) {
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logEntries]);

  return (
    <div className="h-full overflow-y-auto font-mono text-[11px] leading-relaxed pr-1">
      {logEntries.map((entry, i) => (
        <div key={`${entry.ts}-${i}`} className={`${logColor(entry.event)} py-0.5`}>
          <span className="text-gray-600 mr-2">
            {new Date(entry.ts).toLocaleTimeString()}
          </span>
          {entry.line}
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}
