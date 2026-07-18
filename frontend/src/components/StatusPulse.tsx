import { motion, useReducedMotion } from "framer-motion";

export function StatusPulse({ tone = "healthy" }: { tone?: "healthy" | "warning" | "danger" }) {
  const reducedMotion = useReducedMotion();
  const color = tone === "healthy" ? "bg-teal-600" : tone === "warning" ? "bg-amber-500" : "bg-rose-600";

  return (
    <span className="relative inline-flex h-2.5 w-2.5" aria-hidden="true">
      {!reducedMotion && (
        <motion.span
          className={`absolute inset-0 rounded-full ${color}`}
          animate={{ opacity: [0.45, 0], scale: [1, 2.1] }}
          transition={{ duration: 2.4, repeat: Infinity, type: "tween", ease: "easeOut" }}
        />
      )}
      <span className={`relative h-2.5 w-2.5 rounded-full ${color}`} />
    </span>
  );
}
