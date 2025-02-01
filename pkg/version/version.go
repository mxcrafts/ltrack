package version

import (
	"fmt"
)

var (
	Version = "0.0.1"
	Logo    = `
███╗   ███╗██╗  ██╗████████╗██████╗  █████╗  ██████╗██╗  ██╗
████╗ ████║╚██╗██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██╔████╔██║ ╚███╔╝    ██║   ██████╔╝███████║██║     █████╔╝ 
██║╚██╔╝██║ ██╔██╗    ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ 
██║ ╚═╝ ██║██╔╝ ██╗   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗
╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                Version: %s
`
)

// PrintLogo prints the program logo and version information
func PrintLogo() string {
	return fmt.Sprintf(Logo, Version)
}
