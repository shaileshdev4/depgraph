import { useEffect, useRef, useState } from "react";

export function useCountUp(target, duration = 600) {
  const [value, setValue] = useState(0);
  const prev = useRef(0);

  useEffect(() => {
    if (target === prev.current) return;
    const start = prev.current;
    const end = Number(target) || 0;
    const startTime = Date.now();

    const tick = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(start + (end - start) * eased));
      if (progress < 1) requestAnimationFrame(tick);
      else prev.current = end;
    };
    requestAnimationFrame(tick);
  }, [target, duration]);

  return value;
}
