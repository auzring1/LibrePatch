import { useMemo, useState } from "react";
import { useInfiniteQuery, useMutation } from "@tanstack/react-query";
import { Alert, Button, Group, Select, TextInput } from "@mantine/core";
import { api, errorMessage, type AuditEntry } from "../api/client";
import { dateTime } from "../api/format";
import { describeAudit } from "../components/auditText";
import { Card, DataTable, EmptyState, Icons, Page, PageHeader, Status, StatusPill, type Column } from "../ui";

interface Verify {
  intact: boolean;
  checked: number;
  broken_at: number;
  seconds: number;
}

function Outcome({ value }: { value: string }) {
  if (value === "denied")
    return (
      <StatusPill kind="warning" size="sm" icon={Icons.Lock}>
        Denied
      </StatusPill>
    );
  return <Status value={value} size="sm" />;
}

const PAGE = 100;
// A stable empty list: a new [] on every render makes the table reset its page again and again while loading.
const NONE: AuditEntry[] = [];

export function AuditPage() {
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState<string | null>(null);
  const [actor, setActor] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [applied, setApplied] = useState("");
  const query = () => {
    const p = new URLSearchParams();
    if (action.trim()) p.set("action", action.trim());
    if (outcome) p.set("outcome", outcome);
    if (actor.trim()) p.set("actor", actor.trim());
    if (from) p.set("from", new Date(from).toISOString());
    if (to) p.set("to", new Date(to).toISOString());
    return p.toString();
  };
  const q = useInfiniteQuery({
    queryKey: ["audit", applied],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => api<{ items: AuditEntry[] }>("GET", `/audit?limit=${PAGE}${applied ? `&${applied}` : ""}${pageParam ? `&before_id=${pageParam}` : ""}`),
    getNextPageParam: (last) => (last.items.length === PAGE ? last.items[last.items.length - 1]?.id : undefined),
  });
  const verify = useMutation({ mutationFn: () => api<Verify>("POST", "/audit/verify", {}) });
  const items = useMemo(() => q.data?.pages.flatMap((p) => p.items), [q.data]);

  const columns = useMemo<Column<AuditEntry>[]>(
    () => [
      { id: "time", header: "Time", value: (a) => new Date(a.ts).getTime(), sortable: true, width: 190, cell: (a) => <span style={{ whiteSpace: "nowrap" }}>{dateTime(a.ts)}</span>, csv: (a) => a.ts },
      { id: "what", header: "What happened", value: (a) => describeAudit(a), sortable: true, required: true, width: 340, wrap: true },
      { id: "action", header: "Action code", value: (a) => a.action, sortable: true, width: 200 },
      { id: "outcome", header: "Outcome", value: (a) => a.outcome, sortable: true, width: 120, cell: (a) => <Outcome value={a.outcome} /> },
      {
        id: "actor",
        header: "Actor",
        value: (a) => `${a.actor_name || a.actor_type}${a.actor_ip ? ` · ${a.actor_ip}` : ""}`,
        sortable: true,
        width: 240,
      },
      { id: "target", header: "Target", value: (a) => (a.target_type ? `${a.target_type} ${a.target_ids.join(", ").slice(0, 40)}` : "—"), width: 240 },
      {
        id: "details",
        header: "Details",
        defaultHidden: true,
        value: (a) => JSON.stringify(a.details),
        width: 380,
        wrap: true,
        cell: (a) => (
          <code className="lp-mono" style={{ overflowWrap: "anywhere" }}>
            {JSON.stringify(a.details)}
          </code>
        ),
      },
    ],
    [],
  );

  return (
    <Page>
      <PageHeader
        title="Audit log"
        description="Append-only and hash-chained: each entry commits to the one before it, so an edit or deletion anywhere breaks the chain."
        actions={
          <>
            <Button component="a" href={`/api/v1/audit.csv${applied ? `?${applied}` : ""}`} download variant="default" leftSection={<Icons.Download size={16} aria-hidden />}>
              Export CSV
            </Button>
            <Button leftSection={<Icons.NavUpdates size={16} aria-hidden />} onClick={() => verify.mutate()} loading={verify.isPending}>
              Verify the chain
            </Button>
          </>
        }
      />
      {verify.data && (
        <Alert
          color={verify.data.intact ? "green" : "red"}
          role={verify.data.intact ? "status" : "alert"}
          title={verify.data.intact ? "Verification passed" : "Verification failed"}
          icon={verify.data.intact ? <Icons.Success size={18} aria-hidden /> : <Icons.Critical size={18} aria-hidden />}
        >
          {verify.data.intact ? `The chain is intact: ${verify.data.checked} entries checked in ${verify.data.seconds.toFixed(1)} s.` : `The chain is BROKEN at entry ${verify.data.broken_at}. Treat the log from there on as untrustworthy and investigate.`}
        </Alert>
      )}
      {verify.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(verify.error)}
        </Alert>
      )}
      <Card title="Filters" description="Narrow the log on the server, then use the table's search to look within the result.">
        <form onSubmit={(e) => (e.preventDefault(), setApplied(query()))}>
          <Group align="flex-end">
            <TextInput label="Action starts with" placeholder="e.g. user. or deployment" value={action} onChange={(e) => setAction(e.currentTarget.value)} w={220} />
            <Select label="Outcome" data={["success", "denied", "error"]} value={outcome} onChange={setOutcome} clearable placeholder="Any" w={130} />
            <TextInput label="Actor (id or IP)" value={actor} onChange={(e) => setActor(e.currentTarget.value)} w={200} />
            <TextInput label="From" type="datetime-local" value={from} onChange={(e) => setFrom(e.currentTarget.value)} />
            <TextInput label="To" type="datetime-local" value={to} onChange={(e) => setTo(e.currentTarget.value)} />
            <Button type="submit" leftSection={<Icons.Filter size={16} aria-hidden />}>
              Filter
            </Button>
          </Group>
        </form>
      </Card>
      <DataTable<AuditEntry>
        id="audit"
        label="Audit log"
        data={items ?? NONE}
        loading={q.isLoading}
        error={q.error}
        columns={columns}
        rowId={(a) => String(a.id)}
        rowLabel={(a) => `${a.action} at ${a.ts}`}
        searchPlaceholder="Search the entries shown…"
        pageSize={PAGE}
        empty={<EmptyState title="No audit entries" description={applied ? "Nothing matches these filters." : "Entries appear here as people and devices act."} icon={<Icons.NavAudit size={26} />} />}
      />
      {q.hasNextPage && (
        <div>
          <Button variant="light" onClick={() => void q.fetchNextPage()} loading={q.isFetchingNextPage}>
            Load older entries
          </Button>
        </div>
      )}
    </Page>
  );
}
