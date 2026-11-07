import { HoldsCard } from "../components/Holds";
import { useSession } from "../api/session";
import { Page, PageHeader } from "../ui";

/** Updates a ring's failures are holding back, with the release action for people who may use it. */
export function HeldUpdatesPage() {
  const { can } = useSession();
  return (
    <Page>
      <PageHeader title="Held updates" description="Updates that failed a ring's success threshold. Later rings do not receive them until someone looks at the failures and releases the hold or declines the update." />
      <HoldsCard canEdit={can("updates:policy")} always />
    </Page>
  );
}
