import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { Button, Group, Modal, Stack, Text } from "@mantine/core";

export interface ConfirmOptions {
  title: string;
  message?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** A destructive action: the confirm button is red and the label should name what is lost. */
  danger?: boolean;
}

type Ask = (o: ConfirmOptions) => Promise<boolean>;
const Ctx = createContext<Ask>(() => Promise.resolve(false));

/** `const confirm = useConfirm(); if (await confirm({ title: "Delete 3 devices?", danger: true })) ...` */
export const useConfirm = (): Ask => useContext(Ctx);

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [opts, setOpts] = useState<ConfirmOptions | null>(null);
  const resolver = useRef<(v: boolean) => void>(undefined);
  const ask = useCallback<Ask>((o) => new Promise<boolean>((resolve) => ((resolver.current = resolve), setOpts(o))), []);
  const close = (v: boolean) => {
    resolver.current?.(v);
    setOpts(null);
  };
  return (
    <Ctx.Provider value={ask}>
      {children}
      <Modal opened={!!opts} onClose={() => close(false)} title={opts?.title} centered size="md" trapFocus returnFocus>
        <Stack>
          {opts?.message && <Text size="sm">{opts.message}</Text>}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => close(false)} data-autofocus>
              {opts?.cancelLabel ?? "Cancel"}
            </Button>
            <Button color={opts?.danger ? "red" : undefined} onClick={() => close(true)}>
              {opts?.confirmLabel ?? "Confirm"}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Ctx.Provider>
  );
}
