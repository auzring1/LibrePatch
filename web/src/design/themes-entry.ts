// Loads every theme's CSS, plus the shared tokens, the Mantine bridge and the base element styles, in that order.
import "@fontsource-variable/inter";
import "./tokens.css";
import.meta.glob("./themes/*.css", { eager: true });
import "./mantine-bridge.css";
import "./base.css";
