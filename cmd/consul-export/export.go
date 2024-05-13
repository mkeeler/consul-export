package main

import (
	"os"

	"github.com/mitchellh/cli"
	"github.com/mkeeler/consul-export/internal/export/commands"
)

func main() {
	ui := &cli.ColoredUi{
		Ui: &cli.BasicUi{
			Writer:      os.Stdout,
			ErrorWriter: os.Stderr,
		},
		OutputColor: cli.UiColorNone,
		ErrorColor:  cli.UiColorRed,
		InfoColor:   cli.UiColorBlue,
		WarnColor:   cli.UiColorYellow,
	}

	exportCmd, err := commands.NewExport(ui)
	if err != nil {
		ui.Error(err.Error())
		os.Exit(1)
	}

	os.Exit(exportCmd.Run(os.Args[1:]))
}
