package service

import "testing"

func TestValidateConfirm(t *testing.T) {
	if err := ValidateConfirm("УДАЛИТЬ"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfirm("delete"); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestUninstallCommand(t *testing.T) {
	cmd := UninstallCommand(Config{
		Name:       "phantom-proxy",
		ScriptPath: "/opt/deploy/uninstall.sh",
	})
	if cmd != "sudo bash /opt/deploy/uninstall.sh" {
		t.Fatalf("cmd=%q", cmd)
	}
}

func TestScheduleUninstallDisabled(t *testing.T) {
	res := ScheduleUninstall(Config{AllowUninst: false}, false)
	if res.Scheduled {
		t.Fatal("не должно планироваться")
	}
	if res.Command == "" {
		t.Fatal("ожидалась команда")
	}
}
