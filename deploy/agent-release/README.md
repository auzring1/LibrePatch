# Agent release that goes into the server image

This folder is empty in the repository. The image workflow (`.github/workflows/image.yml`) builds and signs the Windows agent first,
copies `librepatch-agent_<version>_windows_amd64.exe` and its signed `librepatch-agent_<version>_windows_amd64.lprel` here, and then
builds the server image, which carries both files in `/opt/librepatch/agent-release`.

The server registers that release by itself (docs/DECISIONS.md D149). Without an update signing key no `.lprel` is made and the
image carries nothing.
