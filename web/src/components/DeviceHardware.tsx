import { SimpleGrid, Stack, Table } from "@mantine/core";
import type { Device } from "../api/client";
import { bytes, dateTime } from "../api/format";
import { Card, EmptyState, Icons, StatusPill } from "../ui";
import { Field } from "./DeviceField";

const bitlockerKind: Record<string, "success" | "danger" | "warning"> = { protected: "success", unprotected: "danger", encrypting: "warning", decrypting: "warning" };

/** Hardware inventory plus the device's client certificates (formerly their own tab). */
export function HardwareTab({ device: d }: { device: Device }) {
  const hw = d.hardware;
  return (
    <Stack>
      {!hw && <EmptyState icon={<Icons.Server size={26} />} title="No hardware inventory yet" description="The device reports its hardware a few minutes after it first connects." />}
      {hw && (
        <>
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <Field label="Manufacturer" value={hw.manufacturer} />
            <Field label="Model" value={hw.model} />
            <Field label="Serial number" value={hw.serial} />
            <Field label="Chassis" value={hw.chassis} />
            <Field label="CPU" value={`${hw.cpu_model ?? ""} (${hw.cpu_logical_cores ?? "?"} logical cores)`} />
            <Field label="Memory" value={bytes(hw.ram_bytes)} />
            <Field label="BIOS" value={hw.bios_version} />
            <Field label="Domain" value={hw.domain} />
            <Field label="Architecture" value={hw.arch} />
            <Field label="Time zone" value={hw.timezone} />
          </SimpleGrid>
          {!!hw.disks?.length && (
            <Table aria-label="Disks">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Disk</Table.Th>
                  <Table.Th>File system</Table.Th>
                  <Table.Th>Size</Table.Th>
                  <Table.Th>Free</Table.Th>
                  <Table.Th>BitLocker</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {hw.disks.map((k) => (
                  <Table.Tr key={k.mount}>
                    <Table.Td>{k.mount}</Table.Td>
                    <Table.Td>{k.filesystem}</Table.Td>
                    <Table.Td>{bytes(k.size_bytes)}</Table.Td>
                    <Table.Td>{bytes(k.free_bytes)}</Table.Td>
                    <Table.Td>
                      {k.bitlocker ? (
                        <StatusPill kind={bitlockerKind[k.bitlocker] ?? "neutral"} size="sm" icon={k.bitlocker === "protected" ? Icons.Lock : undefined}>
                          {k.bitlocker[0]!.toUpperCase() + k.bitlocker.slice(1)}
                        </StatusPill>
                      ) : (
                        "—"
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
          {!!hw.interfaces?.length && (
            <Table aria-label="Network interfaces">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Interface</Table.Th>
                  <Table.Th>MAC</Table.Th>
                  <Table.Th>Addresses</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {hw.interfaces.map((n) => (
                  <Table.Tr key={n.name}>
                    <Table.Td>{n.name}</Table.Td>
                    <Table.Td>{n.mac}</Table.Td>
                    <Table.Td>{n.addresses?.join(", ")}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
        </>
      )}
      <Card title="Device certificate" description="The client certificates this device uses to prove its identity to the server.">
        {!d.certificates?.length && <EmptyState icon={<Icons.Lock size={26} />} title="No certificates" />}
        {!!d.certificates?.length && (
          <Table aria-label="Certificates">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Serial</Table.Th>
                <Table.Th>Expires</Table.Th>
                <Table.Th>State</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {d.certificates.map((c) => (
                <Table.Tr key={c.serial}>
                  <Table.Td ff="monospace" fz="xs">
                    {c.serial.slice(0, 16)}…
                  </Table.Td>
                  <Table.Td>{dateTime(c.not_after)}</Table.Td>
                  <Table.Td>{c.revoked_at ? <StatusPill kind="danger" size="sm">Revoked</StatusPill> : <StatusPill kind="success" size="sm">Valid</StatusPill>}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>
    </Stack>
  );
}
