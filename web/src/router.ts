import { useEffect, useState } from "react";

// Hash routes keep the SPA servable from any static path with no server rewrites.
export function useRoute(): string[] {
  const read = () => (location.hash.replace(/^#\/?/, "") || "queue").split("/").map(decodeURIComponent);
  const [r, setR] = useState(read);
  useEffect(() => {
    const on = () => { setR(read()); window.scrollTo(0, 0); };
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  return r;
}

export const go = (path: string) => { location.hash = `#/${path}`; };
export const href = (path: string) => `#/${path}`;
