// vite empties the output directory; restore the placeholder Go's embed needs.
import { writeFileSync } from "node:fs";
writeFileSync(new URL("../../internal/server/webui/dist/.keep", import.meta.url), "");
