package scheduler

import (
	"strings"
	"testing"
)

func TestWindowsRefreshPrincipalDefaultRunLevel(t *testing.T) {
	for _, tc := range []struct {
		name        string
		replacement string
		accepted    bool
	}{
		{"explicit least privilege", "<RunLevel>LeastPrivilege</RunLevel>", true},
		{"omitted default", "", true},
		{"explicit empty is invalid", "<RunLevel/>", false},
		{"explicit elevated", "<RunLevel>HighestAvailable</RunLevel>", false},
		{"unknown enum", "<RunLevel>SomeFutureLevel</RunLevel>", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, original := legacyWindowsTask(t)
			original = strings.Replace(original, "<RunLevel>LeastPrivilege</RunLevel>", tc.replacement, 1)
			userID, err := windowsPrincipalUserID()
			if err != nil {
				t.Fatal(err)
			}
			_, doc, err := parseWindowsTask(original, cfg.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			if got := validateWindowsRefreshPrincipal(doc, userID); (got == nil) != tc.accepted {
				t.Fatalf("principal validation=%v accepted=%t", got, tc.accepted)
			}
			runner := &refreshTaskRunner{xml: original}
			info, err := RefreshWindows(InstallOptions{Config: cfg, Runner: runner})
			if !tc.accepted {
				if err == nil || runner.creates != 0 {
					t.Fatalf("invalid principal mutated the task: err=%v creates=%d", err, runner.creates)
				}
				return
			}
			if err != nil || !info.Background || runner.creates != 1 {
				t.Fatalf("refresh default principal: info=%+v err=%v creates=%d", info, err, runner.creates)
			}
			_, updated, err := parseWindowsTask(runner.xml, cfg.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			if (updated.Principals[0].RunLevel == nil) != (doc.Principals[0].RunLevel == nil) {
				t.Fatal("refresh must preserve the original representation of RunLevel")
			}
			if _, err := RefreshWindows(InstallOptions{Config: cfg, Runner: runner}); err != nil || runner.creates != 1 {
				t.Fatalf("repeated refresh must not mutate a ready task: %v creates=%d", err, runner.creates)
			}
		})
	}
}

func TestWindowsRefreshPrincipalStillRejectsOtherIdentities(t *testing.T) {
	for _, fault := range []string{"different user", "group identity", "S4U", "Password", "missing logon", "no principals", "multiple principals"} {
		t.Run(fault, func(t *testing.T) {
			cfg, original := legacyWindowsTask(t)
			original = strings.Replace(original, "<RunLevel>LeastPrivilege</RunLevel>", "", 1)
			userID, _ := windowsPrincipalUserID()
			switch fault {
			case "different user":
				original = strings.Replace(original, "<UserId>"+userID+"</UserId>", "<UserId>S-1-5-21-999</UserId>", 1)
			case "group identity":
				original = strings.Replace(original, "<UserId>"+userID+"</UserId>", "<UserId>"+userID+"</UserId><GroupId>S-1-5-32-544</GroupId>", 1)
			case "S4U", "Password":
				original = strings.Replace(original, "<LogonType>InteractiveToken</LogonType>", "<LogonType>"+fault+"</LogonType>", 1)
			case "missing logon":
				original = strings.Replace(original, "<LogonType>InteractiveToken</LogonType>", "", 1)
			case "no principals":
				start, end := strings.Index(original, "<Principals>"), strings.Index(original, "</Principals>")+len("</Principals>")
				original = original[:start] + original[end:]
			case "multiple principals":
				original = strings.Replace(original, "</Principals>", "<Principal><UserId>"+userID+"</UserId><LogonType>InteractiveToken</LogonType></Principal></Principals>", 1)
			}
			runner := &refreshTaskRunner{xml: original}
			if _, err := RefreshWindows(InstallOptions{Config: cfg, Runner: runner}); err == nil || runner.creates != 0 {
				t.Fatalf("unsafe principal must be rejected before mutation: err=%v creates=%d", err, runner.creates)
			}
		})
	}
}
