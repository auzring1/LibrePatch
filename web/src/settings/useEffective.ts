import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useSession } from "../api/session";

export interface CustomFieldDef {
  key: string;
  label: string;
  type: "text" | "select" | "date";
  options: string[];
  show_in_list: boolean;
}

/** The organization's display choices and defaults that every signed-in person may read (GET /settings/effective). */
export interface Effective {
  appearance: { default_density: string; sidebar_style: string; date_format: string; time_format: string; time_zone: string; locale: string; first_day_of_week: string };
  devices: { offline_hours: number; naming_pattern: string; default_columns: string[]; custom_fields: CustomFieldDef[] };
  updates: Record<string, unknown>;
}

export function useEffective() {
  const { session } = useSession();
  return useQuery({ queryKey: ["settings", "effective"], queryFn: () => api<Effective>("GET", "/settings/effective"), enabled: !!session, staleTime: 5 * 60_000 });
}
