package vulns

// osProducts maps a Windows build number to the CPE product the NVD uses for that release. A client and a server release
// can share a build number (Windows 11 24H2 and Windows Server 2025 are both 26100), so the two are listed apart.
var (
	clientOS = map[int][2]string{
		19044: {"windows_10_21h2", "Windows 10 21H2"},
		19045: {"windows_10_22h2", "Windows 10 22H2"},
		22000: {"windows_11_21h2", "Windows 11 21H2"},
		22621: {"windows_11_22h2", "Windows 11 22H2"},
		22631: {"windows_11_23h2", "Windows 11 23H2"},
		26100: {"windows_11_24h2", "Windows 11 24H2"},
		26200: {"windows_11_25h2", "Windows 11 25H2"},
		26300: {"windows_11_26h2", "Windows 11 26H2"},
	}
	serverOS = map[int][2]string{
		14393: {"windows_server_2016", "Windows Server 2016"},
		17763: {"windows_server_2019", "Windows Server 2019"},
		20348: {"windows_server_2022", "Windows Server 2022"},
		26100: {"windows_server_2025", "Windows Server 2025"},
	}
)

// OSProduct returns the CPE product and a readable name for a Windows build, or false for a build that is not tracked. The
// names were written from memory of the NVD's naming and have not been compared with the live CPE dictionary: a wrong one
// simply finds nothing.
func OSProduct(server bool, build int) (cpe, label string, ok bool) {
	m := clientOS
	if server {
		m = serverOS
	}
	p, ok := m[build]
	return p[0], p[1], ok
}
