import { ActionIcon, Tooltip, type ActionIconProps } from "@mantine/core";
import type { ReactNode } from "react";

interface Props extends Omit<ActionIconProps, "children"> {
  /** Required: icon-only buttons need a name for assistive technology; it is also the tooltip. */
  label: string;
  icon: ReactNode;
  onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void;
  disabled?: boolean;
  type?: "button" | "submit";
}

export function IconButton({ label, icon, ...rest }: Props) {
  return (
    <Tooltip label={label} openDelay={350} withArrow>
      <ActionIcon variant="subtle" color="gray" size="md" aria-label={label} {...rest}>
        {icon}
      </ActionIcon>
    </Tooltip>
  );
}
